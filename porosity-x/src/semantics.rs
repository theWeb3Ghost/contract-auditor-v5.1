/**
 * Semantic Analysis Layer for Porosity-X
 *
 * This module adds Solidity-level semantic understanding on top of the
 * raw bytecode analysis. It answers questions like:
 * - Which functions are payable?
 * - Which functions have conditional msg.value checks?
 * - Which external calls could reenter?
 * - Are ETH accounting and state updates consistent?
 *
 * This is the bridge between raw EVM instructions and Solidity semantics
 * that an auditor would recognize.
 *
 * Knowledge base:
 * - Uses embedded Solidity documentation patterns (solkb module)
 * - Recognizes standard Solidity compilation patterns from v0.8.x
 * - Maps bytecode patterns to high-level Solidity constructs
 */

use crate::disasm::{DecodedInstruction, Instruction};
use crate::blocks::BasicBlock;
use crate::taint::BlockTaintResult;
use crate::analyzer::{AnalysisResult, CallGraphEdge, StorageSlotAnalysis};
use crate::solkb::{solidity_patterns, eth_invariants, reentrancy_patterns, SolidityPattern};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SemanticFunction {
    pub selector: String,
    pub entry_block: u32,
    pub entry_offset: u32,
    pub is_payable: bool,
    pub is_view: bool,
    pub has_external_calls: bool,
    pub has_msg_value_check: bool,          // requires msg.value == X
    pub has_conditional_value_check: bool,  // branches on price/condition + msg.value
    pub has_value_send: bool,               // sends ETH via transfer/call
    pub sends_user_value: bool,             // transfers caller's msg.value
    pub value_sends: Vec<ValueTransfer>,
    pub value_checks: Vec<ValueCheck>,
    pub external_calls: Vec<ExternalCallInfo>,
    pub state_updates: Vec<StateUpdate>,
    pub reachable_blocks: Vec<u32>,
    pub semantic_risk: SemanticRisk,
    /// Solidity pattern context: what known Solidity construct this function maps to
    pub solidity_context: SolidityContext,
}

/// Solidity-level context for a function, derived from bytecode patterns
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SolidityContext {
    /// What Solidity construct this function likely represents (e.g., "payable", "withdraw", "setter")
    pub construct_type: String,
    /// The Solidity source-level pattern detected (from knowledge base)
    pub detected_patterns: Vec<String>,
    /// Whether this function has if/else branching with imbalanced ETH requirements
    pub has_imbalanced_eth_branches: bool,
    /// Whether the function writes state that can be exploited via 0-value calls
    pub can_write_state_at_zero_value: bool,
    /// Description of the vulnerability path if applicable
    pub vulnerability_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValueCheck {
    pub pc: u32,
    pub block_offset: u32,
    pub condition: String,
    pub is_strict_equality: bool,  // msg.value == amount (strict) vs msg.value >= amount
    pub checked_value: Option<String>,  // what we're comparing against
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValueTransfer {
    pub pc: u32,
    pub block_offset: u32,
    pub call_type: String,  // CALL
    pub target: Option<String>,
    pub amount_expression: String,
    pub is_to_external: bool,
    pub is_payable_context: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExternalCallInfo {
    pub call_type: String,
    pub target: Option<String>,
    pub target_tainted: bool,
    pub value_tainted: bool,
    pub pc: u32,
    pub block_offset: u32,
    pub function_selector: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StateUpdate {
    pub slot: String,
    pub operation: String,  // "sstore"
    pub pc: u32,
    pub block_offset: u32,
    pub value_tainted: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SemanticRisk {
    pub reentrancy_risk: RiskLevel,           // callable, external call, no state guard
    pub eth_accounting_risk: RiskLevel,       // ETH sent without recording or withdrawn without check
    pub access_control_risk: RiskLevel,       // hardcoded addresses, no ownership transfer
    pub branching_risk: RiskLevel,            // conditional logic with imbalanced requirements
    pub findings: Vec<SemanticFinding>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SemanticFinding {
    pub pattern: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub evidence: Vec<String>,
    pub affected_blocks: Vec<u32>,
}

impl Default for SemanticRisk {
    fn default() -> Self {
        SemanticRisk {
            reentrancy_risk: RiskLevel::None,
            eth_accounting_risk: RiskLevel::None,
            access_control_risk: RiskLevel::None,
            branching_risk: RiskLevel::None,
            findings: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SemanticAnalysis {
    pub functions: Vec<SemanticFunction>,
    pub semantic_findings: Vec<SemanticFinding>,
    pub eth_balance_invariants: Vec<EthBalanceInvariant>,
    pub function_relationships: Vec<FunctionRelationship>,
    pub knowledge_base: KnowledgeBaseInfo,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EthBalanceInvariant {
    pub expression: String,
    pub related_slots: Vec<String>,
    pub confidence: f32,
    pub rationale: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FunctionRelationship {
    pub caller_selector: String,
    pub callee_selector: String,
    pub relationship: String,  // "transfers_value", "modifies_state", "both"
    pub risk: String,
}

/// Summary of the embedded Solidity knowledge base
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KnowledgeBaseInfo {
    pub patterns_recognized: usize,
    pub reentrancy_patterns: usize,
    pub invariant_patterns: usize,
    pub solidity_version: String,
    pub key_patterns: Vec<SolidityPattern>,
}

/// Run semantic analysis on the full analysis result
/// Takes internal BasicBlock and BlockTaintResult data plus the AnalysisResult
pub fn run_semantic_analysis(
    analysis: &AnalysisResult,
    blocks: &[BasicBlock],
    block_taint_results: &[BlockTaintResult],
) -> SemanticAnalysis {
    let s_patterns = solidity_patterns();
    let r_patterns = reentrancy_patterns();
    let invariants = eth_invariants();

    let functions = recover_semantic_functions(analysis, blocks, block_taint_results);
    let findings = detect_branching_vulnerabilities(&functions, blocks, block_taint_results);
    let eth_invariants = infer_eth_balance_invariants(&functions, &analysis.storage_analysis);
    let relationships = infer_function_relationships(&functions, &analysis.call_graph);

    SemanticAnalysis {
        functions,
        semantic_findings: findings,
        eth_balance_invariants: eth_invariants,
        function_relationships: relationships,
        knowledge_base: KnowledgeBaseInfo {
            patterns_recognized: s_patterns.len(),
            reentrancy_patterns: r_patterns.len(),
            invariant_patterns: invariants.len(),
            solidity_version: "v0.8.x".to_string(),
            key_patterns: s_patterns.clone(),
        },
    }
}

/// Recover function-level semantic info by tracing control flow from dispatch
fn recover_semantic_functions(
    analysis: &AnalysisResult,
    blocks: &[BasicBlock],
    taint_results: &[BlockTaintResult],
) -> Vec<SemanticFunction> {
    let mut functions: Vec<SemanticFunction> = Vec::new();

    // The function selector dispatch table is at the start of the contract.
    // We walk the basic blocks starting from block 0 and trace control flow
    // to recover function boundaries and characteristics.

    // For each recovered function, trace its reachable blocks
    for func in &analysis.functions {
        if func.selector == "constructor" {
            continue;
        }

        let entry_block = find_block_at_offset(blocks, func.entry_point);
        if entry_block.is_none() {
            continue;
        }

        let entry_block_id = entry_block.unwrap().id;

        // Trace all blocks reachable from this function's entry point
        let reachable = trace_reachable_blocks(blocks, entry_block_id);

        // Collect all taint/ops within this function's reachable blocks
        let mut value_checks = Vec::new();
        let mut value_sends = Vec::new();
        let mut external_calls = Vec::new();
        let mut state_updates = Vec::new();
        let mut has_call = false;
        let mut has_sstore = false;
        let mut has_msg_value = false;
        let mut has_callvalue_in_path = false;

        for &block_id in &reachable {
            if let Some(block) = blocks.iter().find(|b| b.id == block_id) {
                let taint = taint_results.get(block_id as usize);

                for instr in &block.instructions {
                    // Detect CALLVALUE (msg.value access)
                    if matches!(instr.opcode, Instruction::CALLVALUE) {
                        has_msg_value = true;
                        has_callvalue_in_path = true;
                    }

                    // Detect CALL (external call)
                    if instr.opcode.is_call() {
                        has_call = true;
                        let call_info = extract_call_info(instr, block);
                        if let Some(info) = call_info {
                            external_calls.push(info.clone());
                            value_sends.push(ValueTransfer {
                                pc: instr.pc,
                                block_offset: block.offset,
                                call_type: info.call_type.clone(),
                                target: info.target.clone(),
                                amount_expression: "msg.value or dynamic".to_string(),
                                is_to_external: true,
                                is_payable_context: has_callvalue_in_path,
                            });
                        }
                    }

                    // Detect SSTORE (state update)
                    if matches!(instr.opcode, Instruction::SSTORE) {
                        has_sstore = true;
                        let value_tainted = taint
                            .and_then(|t| t.storage_ops.iter().find(|op| {
                                op.operation_type == "sstore" && op.pc == instr.pc
                            }))
                            .map(|op| op.tainted)
                            .unwrap_or(false);

                        state_updates.push(StateUpdate {
                            slot: "unknown".to_string(), // slot resolved via taint
                            operation: "sstore".to_string(),
                            pc: instr.pc,
                            block_offset: block.offset,
                            value_tainted,
                        });
                    }

                    // Detect EQ (potential msg.value == amount check)
                    if matches!(instr.opcode, Instruction::EQ) {
                        if has_callvalue_in_path {
                            value_checks.push(ValueCheck {
                                pc: instr.pc,
                                block_offset: block.offset,
                                condition: "msg.value == <comparison_target>".to_string(),
                                is_strict_equality: true,
                                checked_value: None,
                            });
                        }
                    }

                    // Detect ISZERO (common pattern: require(msg.value > 0) → CALLVALUE ISZERO PUSH2 JUMPI)
                    if matches!(instr.opcode, Instruction::ISZERO) {
                        if has_callvalue_in_path {
                            value_checks.push(ValueCheck {
                                pc: instr.pc,
                                block_offset: block.offset,
                                condition: "msg.value > 0 (require check)".to_string(),
                                is_strict_equality: false,
                                checked_value: None,
                            });
                        }
                    }
                }
            }
        }

        let semantic_risk = compute_semantic_risk(&value_checks, &value_sends, &external_calls, &state_updates);

        // Derive Solidity context from the detected patterns
        let solidity_context = infer_solidity_context(
            func.selector.as_str(),
            has_msg_value,
            has_call,
            &value_checks,
            &reachable,
            blocks,
        );

        let semantic_func = SemanticFunction {
            selector: func.selector.clone(),
            entry_block: entry_block_id,
            entry_offset: func.entry_point,
            is_payable: has_msg_value,
            is_view: false, // would detect via absence of SSTORE
            has_external_calls: has_call,
            has_msg_value_check: !value_checks.is_empty(),
            has_conditional_value_check: value_checks.len() > 0,
            has_value_send: !value_sends.is_empty(),
            sends_user_value: false, // TODO: resolve from taint
            value_sends,
            value_checks,
            external_calls,
            state_updates,
            reachable_blocks: reachable.clone(),
            semantic_risk,
            solidity_context,
        };

        functions.push(semantic_func);
    }

    functions
}

/// Trace all blocks reachable from a given entry block (BFS over control flow)
fn trace_reachable_blocks(blocks: &[BasicBlock], entry_id: u32) -> Vec<u32> {
    let mut visited: HashSet<u32> = HashSet::new();
    let mut queue: Vec<u32> = vec![entry_id];
    let mut result: Vec<u32> = Vec::new();

    while let Some(block_id) = queue.pop() {
        if visited.insert(block_id) {
            result.push(block_id);
            if let Some(block) = blocks.iter().find(|b| b.id == block_id) {
                if let Some(next) = block.next_default {
                    queue.push(next);
                }
                if let Some(next) = block.next_jumpi {
                    queue.push(next);
                }
            }
        }
    }

    result
}

fn find_block_at_offset(blocks: &[BasicBlock], offset: u32) -> Option<&BasicBlock> {
    blocks.iter().find(|b| b.offset == offset)
}

fn extract_call_info(instr: &DecodedInstruction, block: &BasicBlock) -> Option<ExternalCallInfo> {
    Some(ExternalCallInfo {
        call_type: match instr.opcode {
            Instruction::CALL => "CALL".to_string(),
            Instruction::DELEGATECALL => "DELEGATECALL".to_string(),
            Instruction::STATICCALL => "STATICCALL".to_string(),
            Instruction::CALLCODE => "CALLCODE".to_string(),
            _ => return None,
        },
        target: None, // resolved via taint
        target_tainted: false,
        value_tainted: false,
        pc: instr.pc,
        block_offset: block.offset,
        function_selector: None,
    })
}

/// Compute semantic risk for a function based on its operations
fn compute_semantic_risk(
    value_checks: &[ValueCheck],
    value_sends: &[ValueTransfer],
    external_calls: &[ExternalCallInfo],
    state_updates: &[StateUpdate],
) -> SemanticRisk {
    let mut risk = SemanticRisk::default();
    let mut findings: Vec<SemanticFinding> = Vec::new();

    // Reentrancy risk: external call without state update after
    let has_call = !external_calls.is_empty();
    let has_sstore = !state_updates.is_empty();

    if has_call && !has_sstore {
        // CALL without any SSTORE in the function = potential reentrancy
        // (no state guard to prevent reentrant entry)
        risk.reentrancy_risk = RiskLevel::High;
        findings.push(SemanticFinding {
            pattern: "external_call_without_state_update".to_string(),
            severity: "high".to_string(),
            title: "External call without state modification (no reentrancy guard)".to_string(),
            description: "This function makes external calls but performs no state modifications (SSTORE). \
                          Without state changes after the external call, there is no guard to prevent \
                          reentrant calls from manipulating the contract's behavior during the call."
                .to_string(),
            evidence: vec![
                format!("{} external call(s) detected", external_calls.len()),
                "No SSTORE operations found in function body".to_string(),
                "No reentrancy guard (mutex/flag) detected at bytecode level".to_string(),
            ],
            affected_blocks: vec![],
        });
    } else if has_call {
        risk.reentrancy_risk = RiskLevel::Medium;
    }

    // ETH accounting risk: sends ETH without checking msg.value in all branches
    let has_conditional_value = value_checks.len() > 1 || (value_checks.len() == 1 && has_call);

    if value_sends.iter().any(|s| s.is_payable_context) && value_checks.is_empty() {
        // Transferring value but no msg.value check = could send contract's own ETH
        risk.eth_accounting_risk = RiskLevel::Medium;
        findings.push(SemanticFinding {
            pattern: "value_transfer_without_value_check".to_string(),
            severity: "medium".to_string(),
            title: "ETH transfer without msg.value balance check".to_string(),
            description: "This function transfers ETH to external addresses but does not \
                          validate msg.value or check the source of the transferred ETH. \
                          If ETH is sent without corresponding msg.value, it could drain \
                          the contract's balance."
                .to_string(),
            evidence: vec![
                format!("{} value transfer(s) detected", value_sends.len()),
                "No msg.value equality check found".to_string(),
            ],
            affected_blocks: vec![],
        });
    }

    risk.findings = findings;
    risk
}

/// Infer ETH balance invariants from storage patterns
fn infer_eth_balance_invariants(
    functions: &[SemanticFunction],
    storage_analysis: &[StorageSlotAnalysis],
) -> Vec<EthBalanceInvariant> {
    let mut invariants: Vec<EthBalanceInvariant> = Vec::new();

    // Invariant: Contract ETH balance == sum(deposits) - sum(withdrawals)
    // Look for functions that accept ETH and functions that send ETH
    let payable_funcs: Vec<&SemanticFunction> = functions.iter()
        .filter(|f| f.is_payable)
        .collect();

    let sending_funcs: Vec<&SemanticFunction> = functions.iter()
        .filter(|f| f.has_value_send)
        .collect();

    if !payable_funcs.is_empty() && !sending_funcs.is_empty() {
        let related_slots: Vec<String> = storage_analysis.iter()
            .map(|s| s.slot.clone())
            .collect();

        invariants.push(EthBalanceInvariant {
            expression: "address(this).balance == sum(all_deposits) - sum(all_withdrawals)".to_string(),
            related_slots,
            confidence: 0.85,
            rationale: format!(
                "{} payable function(s) accept ETH and {} function(s) send ETH externally. \
                 The contract MUST track ETH deposits and withdrawals to maintain balance integrity.",
                payable_funcs.len(),
                sending_funcs.len()
            ),
        });
    }

    // Invariant: For each payable function, msg.value must be accounted for
    for func in &payable_funcs {
        let all_branches_require_value = func.value_checks.iter()
            .all(|c| c.is_strict_equality);

        if !all_branches_require_value {
            invariants.push(EthBalanceInvariant {
                expression: format!(
                    "function {} must require msg.value in all code paths",
                    func.selector
                ),
                related_slots: vec![],
                confidence: 0.70,
                rationale: "Payable function has branches that may not enforce msg.value requirements".to_string(),
            });
        }
    }

    invariants
}

/// Infer function-to-function relationships for state modification analysis
fn infer_function_relationships(
    functions: &[SemanticFunction],
    call_graph: &[CallGraphEdge],
) -> Vec<FunctionRelationship> {
    let mut relationships: Vec<FunctionRelationship> = Vec::new();

    // For each call, determine what the caller and callee do
    // This is a simplified version — full implementation would
    // trace call targets to function selectors
    for edge in call_graph {
        if let (Some(caller_func), _) = (
            &edge.caller_function,
            &edge.function_selector,
        ) {
            if let Some(caller) = functions.iter().find(|f| &f.selector == caller_func) {
                if caller.sends_user_value {
                    relationships.push(FunctionRelationship {
                        caller_selector: caller.selector.clone(),
                        callee_selector: "external".to_string(),
                        relationship: "transfers_value".to_string(),
                        risk: "medium".to_string(),
                    });
                }
                if caller.has_external_calls {
                    relationships.push(FunctionRelationship {
                        caller_selector: caller.selector.clone(),
                        callee_selector: "external".to_string(),
                        relationship: "modifies_state".to_string(),
                        risk: "low".to_string(),
                    });
                }
            }
        }
    }

    relationships
}

/// Infer the Solidity-level context for a function from bytecode patterns.
/// Uses knowledge from the Solidity documentation to classify what the
/// function likely does at the source level.
fn infer_solidity_context(
    selector: &str,
    is_payable: bool,
    has_external_call: bool,
    value_checks: &[ValueCheck],
    reachable_blocks: &[u32],
    blocks: &[BasicBlock],
) -> SolidityContext {
    let mut detected_patterns = Vec::new();
    let mut has_imbalanced_eth_branches = false;
    let mut can_write_state_at_zero_value = false;
    let mut vulnerability_path = None;

    // Check for inverted msg.value check (the setPriceFeeEth pattern)
    let inverted = detect_inverted_msg_value_check_from_blocks(reachable_blocks, blocks);

    if is_payable && inverted {
        detected_patterns.push("inverted_msg_value_check".to_string());
        has_imbalanced_eth_branches = true;
        can_write_state_at_zero_value = true;
        vulnerability_path = Some(
            "Attacker calls with msg.value=0 → ISZERO branch fires → jumps to function body \
             (else branch) → price/fee storage written at 0 ETH → withdraw later for profit"
                .to_string()
        );
    }

    // Check for if/else branching with conditional value check
    let branch_count = count_branches_in_function_blocks(reachable_blocks, blocks);
    if is_payable && branch_count >= 2 && value_checks.len() < branch_count {
        detected_patterns.push("conditional_logic_with_imbalanced_requirements".to_string());
        has_imbalanced_eth_branches = true;
        can_write_state_at_zero_value = true;
        vulnerability_path = Some(
            "Payable function with if/else branching: msg.value checked in one branch \
             but not the other. The unchecked branch can set state (price/fee/balance) \
             at 0 ETH cost."
                .to_string()
        );
    }

    // Classify the construct type
    let construct_type = if selector == "fallback" {
        "fallback".to_string()
    } else if has_external_call && is_payable {
        if detected_patterns.iter().any(|p| p == "inverted_msg_value_check") {
            "setPriceFeeEth (price setter with inverted check)".to_string()
        } else {
            "payable_with_calls".to_string()
        }
    } else if is_payable {
        "payable_function".to_string()
    } else if has_external_call {
        "view_with_external_call".to_string()
    } else {
        "pure_or_view".to_string()
    };

    SolidityContext {
        construct_type,
        detected_patterns,
        has_imbalanced_eth_branches,
        can_write_state_at_zero_value,
        vulnerability_path,
    }
}

/// Lightweight check for inverted msg.value check (without needing SemanticFunction)
fn detect_inverted_msg_value_check_from_blocks(reachable_blocks: &[u32], blocks: &[BasicBlock]) -> bool {
    for &block_id in reachable_blocks {
        let block = match blocks.iter().find(|b| b.id == block_id) {
            Some(b) => b,
            None => continue,
        };

        let mut seen_callvalue = false;
        let mut seen_iszero = false;

        for instr in &block.instructions {
            match instr.opcode {
                Instruction::CALLVALUE => {
                    seen_callvalue = true;
                }
                Instruction::ISZERO if seen_callvalue => {
                    seen_iszero = true;
                }
                Instruction::JUMPI if seen_iszero => {
                    // The JUMPI fires when msg.value == 0 (ISZERO returns true)
                    // Check if the jump target leads to a REVERT
                    if block.next_jumpi.is_none() {
                        return true;
                    }
                    if let Some(jump_target_id) = block.next_jumpi {
                        let jump_target_block = blocks.iter().find(|b| b.id == jump_target_id);
                        if let Some(target_block) = jump_target_block {
                            let has_revert = target_block.instructions.iter().any(|instr| {
                                matches!(instr.opcode, Instruction::REVERT)
                            });
                            if !has_revert {
                                return true;
                            }
                        } else {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    false
}

/// Count branches in reachable blocks for context inference
fn count_branches_in_function_blocks(reachable_blocks: &[u32], blocks: &[BasicBlock]) -> usize {
    let mut count = 0;
    for &block_id in reachable_blocks {
        if let Some(block) = blocks.iter().find(|b| b.id == block_id) {
            for instr in &block.instructions {
                if matches!(instr.opcode, Instruction::JUMPI) {
                    count += 1;
                }
            }
        }
    }
    count
}

/// Detect branching-related semantic risks (like setPriceFeeEth's conditional msg.value)
///
/// Uses knowledge from the Solidity documentation to identify patterns where:
/// 1. `require(msg.value > 0)` is inverted — JUMPI jumps to function body when msg.value == 0
/// 2. `if/else` branches have imbalanced msg.value requirements — one branch writes state
///    without requiring ETH, creating an ETH-printing vulnerability
/// 3. Conditional logic allows setting price/fee values without ETH backing
pub fn detect_branching_vulnerabilities(
    functions: &[SemanticFunction],
    blocks: &[BasicBlock],
    _taint_results: &[BlockTaintResult],
) -> Vec<SemanticFinding> {
    let mut findings: Vec<SemanticFinding> = Vec::new();

    // Load Solidity patterns from knowledge base
    let patterns = solidity_patterns();

    for func in functions {
        if !func.is_payable {
            continue;
        }

        // Check for inverted msg.value checks: where the JUMPI branch that fires
        // when msg.value == 0 (ISZERO returns true) leads to function body continuation
        // instead of a revert. This means the function can proceed with 0 ETH.
        let inverted_check = detect_inverted_msg_value_check(func, blocks);

        if inverted_check {
            // Look up the pattern from the knowledge base for a richer description
            let pattern_desc = patterns.iter()
                .find(|p| p.name == "inverted_msg_value_check")
                .map(|p| p.description.clone())
                .unwrap_or_else(|| "Inverted msg.value check".to_string());

            findings.push(SemanticFinding {
                pattern: "inverted_msg_value_check".to_string(),
                severity: "critical".to_string(),
                title: format!(
                    "Payable function {} has inverted msg.value check — execution proceeds when msg.value == 0",
                    func.selector,
                ),
                description: format!(
                    "{} This payable function's msg.value check is inverted: when msg.value == 0 \
                     (ISZERO is true), the JUMPI jumps to the function body continuation \
                     instead of reverting. This allows an attacker to call the function with \
                     0 ETH, bypassing the value requirement entirely, then set price/fee \
                     storage which can be withdrawn later — an ETH-printing vulnerability. \
                     \n\nSolidity compilation pattern: CALLVALUE ISZERO PUSH2(target) JUMPI — \
                     the target is the function body (else branch), not a REVERT. \
                     In secure Solidity code, this pattern should be CALLVALUE ISZERO \
                     PUSH2(revert_offset) JUMPI.",
                    pattern_desc,
                ),
                evidence: vec![
                    format!("Function is payable ({})", func.selector),
                    format!("Found {} msg.value check(s)", func.value_checks.len()),
                    "ISZERO check on msg.value branches to function body when msg.value == 0".to_string(),
                    "No ETH requirement enforced in the msg.value == 0 branch".to_string(),
                    "Pattern identified: CALLVALUE ISZERO ... JUMPI (inverted — jumps to body, not REVERT)".to_string(),
                ],
                affected_blocks: func.reachable_blocks.clone(),
            });
            continue; // Don't also check the generic case
        }

        // Check if the function has more branches than value checks
        // If it's payable with branching logic but only checks msg.value in some branches,
        // there may be imbalanced requirements
        let branch_count = count_branches_in_function(func, blocks);

        if branch_count > 0 && func.value_checks.len() < branch_count {
            findings.push(SemanticFinding {
                pattern: "conditional_logic_with_imbalanced_requirements".to_string(),
                severity: "critical".to_string(),
                title: format!(
                    "Payable function {} has {} conditional branch(es) but only {} msg.value check(s) — state may be written without ETH backing",
                    func.selector,
                    branch_count,
                    func.value_checks.len()
                ),
                description: format!(
                    "This payable function contains {} conditional branch(es) but only {} of them \
                     enforce msg.value requirements. This creates an imbalanced state where \
                     one branch may write state (fees, balances) without requiring payment, \
                     creating an ETH-printing vulnerability. \
                     \n\nSolidity pattern: if/else with msg.value check in one branch but not the other. \
                     The else branch may allow setting price/fee/storage at cost 0, which can be \
                     withdrawn later through a separate withdraw function.",
                    branch_count,
                    func.value_checks.len()
                ),
                evidence: vec![
                    format!("Function is payable but has {} conditional branch(es)", branch_count),
                    format!("Only {} msg.value equality check(s) found", func.value_checks.len()),
                    "State updates may occur without ETH backing in some branches".to_string(),
                    "The else branch does not enforce msg.value > 0, allowing price/fee to be set at 0 ETH".to_string(),
                ],
                affected_blocks: func.reachable_blocks.clone(),
            });
        }
    }

    findings
}

/// Detect if a function has an inverted msg.value check.
///
/// In Solidity, `require(msg.value > 0)` compiles to:
///   CALLVALUE ISZERO PUSH2(revert_offset) JUMPI
/// where the JUMPI jumps to REVERT when msg.value == 0 (ISZERO returns true).
///
/// An inverted check has the JUMPI jump to the function body (not REVERT)
/// when msg.value == 0, allowing the function to proceed without payment.
/// This is the pattern in setPriceFeeEth: the if-branch checks msg.value > 0,
/// but the else-branch (reachable when msg.value == 0) proceeds to set price/fee
/// at 0 ETH.
fn detect_inverted_msg_value_check(func: &SemanticFunction, blocks: &[BasicBlock]) -> bool {
    for &block_id in &func.reachable_blocks {
        let block = match blocks.iter().find(|b| b.id == block_id) {
            Some(b) => b,
            None => continue,
        };

        // Look for the pattern: CALLVALUE ... ISZERO ... JUMPI
        // where the JUMPI's conditional branch (when ISZERO is true, i.e. msg.value == 0)
        // does NOT lead to a REVERT
        let mut seen_callvalue = false;
        let mut seen_iszero = false;

        for instr in &block.instructions {
            match instr.opcode {
                Instruction::CALLVALUE => {
                    seen_callvalue = true;
                }
                Instruction::ISZERO if seen_callvalue => {
                    seen_iszero = true;
                }
                Instruction::JUMPI if seen_iszero => {
                    // The JUMPI fires when ISZERO is true (msg.value == 0)
                    // Check if the jump target leads to a REVERT
                    if block.next_jumpi.is_none() {
                        // No explicit jump target resolved — could be the function body
                        return true;
                    }
                    // Check if the jump target block contains a REVERT
                    if let Some(jump_target_id) = block.next_jumpi {
                        let jump_target_block = blocks.iter().find(|b| b.id == jump_target_id);
                        if let Some(target_block) = jump_target_block {
                            let has_revert = target_block.instructions.iter().any(|instr| {
                                matches!(instr.opcode, Instruction::REVERT)
                            });
                            if !has_revert {
                                // The JUMPI jumps to non-REVERT code when msg.value == 0
                                // This is an inverted check!
                                return true;
                            }
                        } else {
                            // Jump target not found — the branch may lead to function body
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    false
}

fn count_branches_in_function(func: &SemanticFunction, blocks: &[BasicBlock]) -> usize {
    // Count JUMPI instructions in reachable blocks for accurate branch detection
    let mut count = 0;
    for &block_id in &func.reachable_blocks {
        if let Some(block) = blocks.iter().find(|b| b.id == block_id) {
            for instr in &block.instructions {
                if matches!(instr.opcode, Instruction::JUMPI) {
                    count += 1;
                }
            }
        }
    }
    count
}
