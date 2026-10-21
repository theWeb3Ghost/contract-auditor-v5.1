use crate::disasm::{decode_bytecode, DecodedInstruction, Instruction};
use crate::blocks::{build_basic_blocks, BasicBlock};
use crate::taint::{analyze_block_taint, BlockTaintResult};
use crate::semantics::{run_semantic_analysis, SemanticAnalysis};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Result of analyzing a contract's bytecode
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AnalysisResult {
    pub version: String,
    pub contract_address: String,
    pub runtime_bytecode_hash: String,
    pub functions: Vec<FunctionInfo>,
    pub basic_blocks: Vec<BlockInfo>,
    pub call_graph: Vec<CallGraphEdge>,
    pub taint_sources: Vec<TaintSourceInfo>,
    pub storage_analysis: Vec<StorageSlotAnalysis>,
    pub external_dependencies: Vec<ExternalDependency>,
    pub reentrancy_analysis: Vec<ReentrancyFinding>,
    pub invariant_candidates: Vec<InvariantCandidate>,
    pub control_flow_structures: Vec<ControlFlowStructure>,
    pub semantic_analysis: Option<SemanticAnalysis>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FunctionInfo {
    pub selector: String,
    pub name: Option<String>,
    pub entry_point: u32,
    pub entry_block: u32,
    pub type_: String,  // "function", "constructor", "fallback", "unknown"
    pub is_payable: bool,
    pub estimated_gas: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockInfo {
    pub id: u32,
    pub offset: u32,
    pub size: u32,
    pub instructions: Vec<InstructionInfo>,
    pub successors: Vec<u32>,
    pub predecessors: Vec<u32>,
    pub flags: Vec<String>,
    pub dominators: Vec<u32>,
    pub calls: Vec<ExternalCallInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InstructionInfo {
    pub pc: u32,
    pub opcode: String,
    pub immediate: String,
    pub opcode_byte: u8,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExternalCallInfo {
    pub call_type: String,
    pub target: Option<String>,
    pub target_tainted: bool,
    pub value: Option<String>,
    pub value_tainted: bool,
    pub reentrancy_risk: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CallGraphEdge {
    pub caller_block: u32,
    pub caller_function: Option<String>,
    pub callee: Option<String>,
    pub call_type: String,
    pub target_tainted: bool,
    pub target_is_external: bool,
    pub target_known: bool,
    pub target_address: Option<String>,
    pub value_tainted: bool,
    pub function_selector: Option<String>,
    pub reentrancy_risk: String,
    pub block_offset: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TaintSourceInfo {
    pub source_type: String,
    pub description: String,
    pub block_offset: u32,
    pub pc: u32,
    pub slot_or_offset: Option<u32>,
    pub reachable_sstore: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StorageSlotAnalysis {
    pub slot: String,
    pub slot_u64: u64,
    pub label: Option<String>,
    pub operations: Vec<StorageOpInfo>,
    pub always_written_with: Vec<String>,  // slots written in same block
    pub is_total_supply: Option<bool>,
    pub is_balance_mapping: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StorageOpInfo {
    pub op_type: String,  // "sload" or "sstore"
    pub block_offset: u32,
    pub pc: u32,
    pub tainted: bool,
    pub value_tainted: Option<bool>,  // only for sstore
    pub slot_tainted: Option<bool>,   // only for sstore
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExternalDependency {
    pub address: String,
    pub call_type: String,
    pub first_seen: u32,
    pub first_seen_pc: u32,
    pub call_count: u32,
    pub target_is_constant: bool,
    pub caller_functions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReentrancyFinding {
    pub pattern: String,
    pub call_offset: u32,
    pub sstore_offset: Option<u32>,
    pub call_value_tainted: bool,
    pub has_guard: bool,
    pub risk: String,
    pub block_id: u32,
    pub details: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InvariantCandidate {
    pub expression: String,
    pub slots: Vec<String>,
    pub confidence: f32,
    pub rationale: String,
    pub supporting_evidence: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ControlFlowStructure {
    pub offset: u32,
    pub structure_type: String,  // "if", "while", "for", "if_else"
    pub condition: Option<String>,
    pub block_range: [u32; 2],  // [start, end] block IDs
}

/// Run the full analysis pipeline
pub fn analyze(bytecode_hex: &str, contract_address: &str) -> anyhow::Result<AnalysisResult> {
    // Strip 0x prefix if present
    let hex_str = bytecode_hex.strip_prefix("0x").unwrap_or(bytecode_hex);

    // Decode hex to bytes
    let bytecode = hex::decode(hex_str)
        .map_err(|e| anyhow::anyhow!("Invalid hex bytecode: {}", e))?;

    // Hash the bytecode
    let bytecode_hash = compute_keccak256(&bytecode);

    // Phase 1: Disassemble
    let instructions = decode_bytecode(&bytecode);

    // Phase 2: Build basic blocks + CFG
    let mut blocks = build_basic_blocks(&instructions, &bytecode);

    // Phase 3: Taint analysis per block
    let mut block_taint_results: Vec<BlockTaintResult> = blocks
        .iter()
        .map(analyze_block_taint)
        .collect();

    // Phase 3b: Propagate NoMoreSSTORE flag across blocks (successors inherit from predecessors)
    // This models the fact that after an external call, subsequent blocks are in "unsafe" context
    propagate_reentrancy_flags(&mut blocks, &mut block_taint_results);

    // Phase 4: Aggregate and correlate
    let functions = recover_functions(&blocks, &instructions);
    let call_graph = build_call_graph(&blocks, &block_taint_results, &functions);
    let taint_sources = extract_taint_sources(&block_taint_results, &blocks);
    let storage_analysis = analyze_storage(&block_taint_results, &blocks);
    let external_deps = find_external_dependencies(&block_taint_results, &blocks);
    let reentrancy = analyze_reentrancy(&block_taint_results, &blocks);
    let invariants = infer_invariants(&storage_analysis, &block_taint_results);
    let control_flow = detect_control_flow(&blocks);

    // Run semantic analysis layer
    // Run semantic analysis layer
    let semantic_result = run_semantic_analysis(
        &AnalysisResult {
            version: "0.1".to_string(),
            contract_address: contract_address.to_string(),
            runtime_bytecode_hash: bytecode_hash.clone(),
            functions: functions.clone(),
            basic_blocks: info_blocks(&blocks, &block_taint_results),
            call_graph: call_graph.clone(),
            taint_sources: taint_sources.clone(),
            storage_analysis: storage_analysis.clone(),
            external_dependencies: external_deps.clone(),
            reentrancy_analysis: reentrancy.clone(),
            invariant_candidates: invariants.clone(),
            control_flow_structures: control_flow.clone(),
            semantic_analysis: None,
        },
        &blocks,
        &block_taint_results,
    );

    // Merge semantic findings into reentrancy analysis
    let mut merged_reentrancy = reentrancy;
    for finding in &semantic_result.semantic_findings {
        merged_reentrancy.push(ReentrancyFinding {
            pattern: finding.pattern.clone(),
            call_offset: 0,
            sstore_offset: None,
            call_value_tainted: false,
            has_guard: false,
            risk: finding.severity.clone(),
            block_id: 0,
            details: finding.description.clone(),
        });
    }

    // Add semantic findings as invariant candidates too
    let mut merged_invariants = invariants;
    for inv in &semantic_result.eth_balance_invariants {
        merged_invariants.push(crate::analyzer::InvariantCandidate {
            expression: inv.expression.clone(),
            slots: inv.related_slots.clone(),
            confidence: inv.confidence,
            rationale: inv.rationale.clone(),
            supporting_evidence: vec!["Semantic analysis: ETH balance invariant".to_string()],
        });
    }

    Ok(AnalysisResult {
        version: "0.1".to_string(),
        contract_address: contract_address.to_string(),
        runtime_bytecode_hash: bytecode_hash,
        functions,
        basic_blocks: info_blocks(&blocks, &block_taint_results),
        call_graph,
        taint_sources,
        storage_analysis,
        external_dependencies: external_deps,
        reentrancy_analysis: merged_reentrancy,
        invariant_candidates: merged_invariants,
        control_flow_structures: control_flow,
        semantic_analysis: Some(semantic_result),
    })
}

/// Compute keccak256 hash of bytecode
fn compute_keccak256(data: &[u8]) -> String {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("0x{}", hex::encode(result))
}

/// Recover function selectors from bytecode
/// Looks for PUSH4 + (AND|EQ) + ... + EQ patterns (selector comparisons)
/// Standard Solidity dispatcher pattern: PUSH4(sel) AND DUP1 PUSH4(sel2) EQ JUMPI
fn recover_functions(blocks: &[BasicBlock], instructions: &[DecodedInstruction]) -> Vec<FunctionInfo> {
    let mut functions: Vec<FunctionInfo> = Vec::new();
    let mut seen_selectors: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Pattern: PUSH4(selector) [AND | EQ] ... JUMPI
    // Standard Solidity dispatcher: PUSH4(sel) AND DUP1 PUSH4(sel2) EQ JUMPI
    // Simple dispatcher: PUSH4(sel) EQ
    let mut i = 0;
    while i < instructions.len() {
        if let Instruction::UNKNOWN(b) = instructions[i].opcode {
            // Guard against underflow: only treat as PUSH when b is actually
            // in the PUSH1..PUSH32 range (0x60..=0x7f). For any other UNKNOWN
            // opcode, skip — it is not a function-selector pattern.
            if b >= 0x60 && b <= 0x7f {
                let push_size = b - 0x60 + 1;
                if push_size == 4 {
                    // PUSH4 — extract selector
                    let selector = format!("0x{}", hex::encode(&instructions[i].immediate));

                    // Check what follows: AND (0x16) is common in Solidity dispatch,
                    // or directly EQ for simple dispatch
                    let mut j = i + 1;
                    let mut found_selector = false;

                    // Skip AND instructions (part of selector masking pattern)
                    while j < instructions.len() && matches!(instructions[j].opcode, Instruction::AND) {
                        j += 1;
                    }

                    // Look for EQ within the next few instructions
                    let search_end = std::cmp::min(j + 8, instructions.len());
                    for k in j..search_end {
                        if matches!(instructions[k].opcode, Instruction::EQ) {
                            found_selector = true;
                            break;
                        }
                        // If we hit another PUSH4, this might be a new selector pair
                        if let Instruction::UNKNOWN(b2) = instructions[k].opcode {
                            if (0x60..=0x7f).contains(&b2) {
                                break;
                            }
                        }
                    }

                    if found_selector && !seen_selectors.contains(&selector) {
                        seen_selectors.insert(selector.clone());

                        // Find the JUMPDEST that follows — search forward from this PUSH4
                        let entry_point = find_selector_entry(&instructions[i + 1..]);

                        // Find the block that contains the entry point
                        let entry_block = blocks.iter()
                            .find(|b| b.offset <= entry_point && b.offset + b.size > entry_point)
                            .map(|b| b.id)
                            .unwrap_or(0);

                        functions.push(FunctionInfo {
                            selector,
                            name: None,
                            entry_point,
                            entry_block,
                            type_: "function".to_string(),
                            is_payable: false,
                            estimated_gas: None,
                        });
                    }
                }
            }
        }
        i += 1;
    }

    // Also check for constructor patterns (first block is often constructor)
    if let Some(first_block) = blocks.first() {
        // If first block doesn't have a selector check, it might be constructor
        let has_selector = first_block.instructions.iter().any(|instr| {
            if let Instruction::UNKNOWN(b) = &instr.opcode {
                b >= &0x60 && b <= &0x7f
            } else {
                false
            }
        });

        if !has_selector && !functions.is_empty() {
            // Potential constructor
            functions.insert(0, FunctionInfo {
                selector: "constructor".to_string(),
                name: None,
                entry_point: 0,
                entry_block: 0,
                type_: "constructor".to_string(),
                is_payable: false,
                estimated_gas: None,
            });
        }
    }

    functions
}

fn find_selector_entry(instructions: &[DecodedInstruction]) -> u32 {
    // In Solidity's dispatch pattern: PUSH4(sel) EQ PUSH2(target) JUMPI
    // The target is the function entry point (a JUMPDEST at that PC).
    // Look for PUSH2 immediately after the EQ.
    for i in 0..instructions.len() {
        if matches!(instructions[i].opcode, Instruction::EQ) {
            // Check if next instruction is PUSH2 (or PUSH1 for smaller targets)
            if i + 1 < instructions.len() {
                let next = &instructions[i + 1];
                if let Instruction::UNKNOWN(b) = next.opcode {
                    if (0x60..=0x7f).contains(&b) && !next.immediate.is_empty() {
                        return parse_push_value(&next.immediate);
                    }
                }
            }
        }
    }
    // Fallback: look for JUMPDEST within the next 10 instructions
    for instr in instructions.iter().take(10) {
        if instr.opcode.is_jumpdest() {
            return instr.pc;
        }
    }
    0
}

fn parse_push_value(bytes: &[u8]) -> u32 {
    let mut val: u32 = 0;
    for &b in bytes.iter().take(4) {
        val = (val << 8) | (b as u32);
    }
    val
}

/// Build call graph edges from external calls found during taint analysis
fn build_call_graph(
    blocks: &[BasicBlock],
    taint_results: &[BlockTaintResult],
    functions: &[FunctionInfo],
) -> Vec<CallGraphEdge> {
    let mut edges: Vec<CallGraphEdge> = Vec::new();

    // Map block offset to function selector
    let mut block_to_func: HashMap<u32, &FunctionInfo> = HashMap::new();
    for func in functions {
        for block in blocks {
            if block.offset <= func.entry_point && block.offset + block.size > func.entry_point {
                block_to_func.insert(block.id, func);
            }
        }
    }

    for (i, taint) in taint_results.iter().enumerate() {
        let block = &blocks[i];
        for call in &taint.external_calls {
            let caller_func = block_to_func.get(&block.id)
                .map(|f| f.selector.clone());

            edges.push(CallGraphEdge {
                caller_block: block.id,
                caller_function: caller_func,
                callee: call.target_address.clone(),
                call_type: call.call_type.clone(),
                target_tainted: call.target_tainted,
                target_is_external: !call.target_known,
                target_known: call.target_known,
                target_address: call.target_address.clone(),
                value_tainted: call.value_tainted,
                function_selector: None,
                reentrancy_risk: call.reentrancy_risk.clone(),
                block_offset: block.offset,
            });
        }
    }

    edges
}

/// Extract and annotate taint sources
fn extract_taint_sources(
    taint_results: &[BlockTaintResult],
    blocks: &[BasicBlock],
) -> Vec<TaintSourceInfo> {
    let mut sources: Vec<TaintSourceInfo> = Vec::new();
    let mut seen: std::collections::HashSet<(String, u32)> = std::collections::HashSet::new();

    for (i, taint) in taint_results.iter().enumerate() {
        let block = &blocks[i];

        // Check if calldata or msg.sender etc. reaches an SSTORE
        let reaches_sstore = taint.storage_ops.iter().any(|op| {
            op.operation_type == "sstore" && op.tainted
        });

        for src in &taint.taint_sources {
            let key = (src.source_type.clone(), src.block_offset);
            if seen.insert(key) {
                sources.push(TaintSourceInfo {
                    source_type: src.source_type.clone(),
                    description: src.description.clone(),
                    block_offset: src.block_offset,
                    pc: src.pc,
                    slot_or_offset: src.slot_or_offset,
                    reachable_sstore: reaches_sstore.then_some(reaches_sstore),
                });
            }
        }
    }

    sources
}

/// Analyze storage slot access patterns
fn analyze_storage(
    taint_results: &[BlockTaintResult],
    blocks: &[BasicBlock],
) -> Vec<StorageSlotAnalysis> {
    let mut slot_ops: HashMap<u64, Vec<(usize, &crate::taint::StorageOperation)>> = HashMap::new();

    for (i, taint) in taint_results.iter().enumerate() {
        for op in &taint.storage_ops {
            slot_ops.entry(op.slot).or_default().push((i, op));
        }
    }

    let mut results: Vec<StorageSlotAnalysis> = Vec::new();

    for (slot, ops) in slot_ops {
        // Determine which slots are always written together (in the same block)
        let mut co_writes: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for (block_idx, _) in &ops {
            let block = &blocks[*block_idx];
            // Find all SSTORE ops in the same block
            for op in &taint_results[*block_idx].storage_ops {
                if op.operation_type == "sstore" && op.slot != slot {
                    co_writes.insert(op.slot);
                }
            }
        }

        // Check if this looks like a total supply (written alongside balances)
        let is_total_supply = ops.iter().any(|(_, op)| {
            op.operation_type == "sstore" && op.tainted
        });

        let always_written_with: Vec<String> = co_writes.iter()
            .map(|s| format!("0x{:x}", s))
            .collect();

        let operations: Vec<StorageOpInfo> = ops.iter()
            .map(|(_, op)| StorageOpInfo {
                op_type: op.operation_type.clone(),
                block_offset: op.block_offset,
                pc: op.pc,
                tainted: op.tainted,
                value_tainted: None,
                slot_tainted: None,
            })
            .collect();

        results.push(StorageSlotAnalysis {
            slot: format!("0x{:x}", slot),
            slot_u64: slot,
            label: guess_slot_label(slot, &always_written_with),
            operations,
            always_written_with,
            is_total_supply: is_total_supply.then_some(is_total_supply),
            is_balance_mapping: None,
        });
    }

    results.sort_by_key(|r| r.slot_u64);
    results
}

fn guess_slot_label(slot: u64, co_writes: &[String]) -> Option<String> {
    if slot == 0 {
        return Some("totalSupply_or_owner".to_string());
    }
    if slot == 1 {
        if co_writes.contains(&"0x0".to_string()) {
            return Some("minter_or_proxy_admin".to_string());
        }
        return Some("owner_or_pauser".to_string());
    }
    if co_writes.contains(&"0x0".to_string()) && co_writes.len() > 1 {
        return Some("balance_mapping".to_string());
    }
    None
}

/// Find all external contract dependencies
fn find_external_dependencies(
    taint_results: &[BlockTaintResult],
    blocks: &[BasicBlock],
) -> Vec<ExternalDependency> {
    let mut deps: HashMap<String, ExternalDependency> = HashMap::new();

    for (i, taint) in taint_results.iter().enumerate() {
        let block = &blocks[i];
        for call in &taint.external_calls {
            if let Some(ref addr) = call.target_address {
                deps.entry(addr.clone()).or_insert_with(|| ExternalDependency {
                    address: addr.clone(),
                    call_type: call.call_type.clone(),
                    first_seen: block.offset,
                    first_seen_pc: 0,
                    call_count: 0,
                    target_is_constant: call.target_known,
                    caller_functions: Vec::new(),
                }).call_count += 1;
            }
        }
    }

    deps.into_values().collect()
}

/// Propagate NoMoreSSTORE flag from blocks with external calls to their successors
/// This models reentrancy context: after a CALL, subsequent blocks that modify state
/// are in a "dangerous" context where reentrant calls could manipulate state mid-execution
fn propagate_reentrancy_flags(
    blocks: &mut [BasicBlock],
    taint_results: &mut [BlockTaintResult],
) {
    // First pass: collect which blocks set the no_more_sstore flag from taint analysis
    let _call_blocks: Vec<u32> = taint_results.iter()
        .filter(|t| t.has_call && t.no_more_sstore)
        .map(|t| t.block_id)
        .collect();

    // Also check the block flags directly (set during basic block construction)
    for block in blocks.iter() {
        if block.flags.no_more_sstore {
            // Mark taint results for this block
            if let Some(t) = taint_results.get_mut(block.id as usize) {
                t.no_more_sstore = true;
            }
        }
    }

    // Second pass: propagate to successors iteratively (fixpoint)
    let mut changed = true;
    let mut iterations = 0;
    while changed && iterations < 50 {
        changed = false;
        iterations += 1;

        // Collect blocks that currently have the flag set
        let flagged_blocks: Vec<u32> = blocks.iter()
            .filter(|b| b.inherit_flags.no_more_sstore || b.flags.no_more_sstore)
            .map(|b| b.id)
            .collect();

        // Also include blocks from taint results
        let mut all_flagged: std::collections::HashSet<u32> = flagged_blocks.into_iter().collect();
        for (i, t) in taint_results.iter().enumerate() {
            if t.no_more_sstore {
                all_flagged.insert(i as u32);
            }
        }

        // Propagate to successors
        let mut updates: Vec<(u32, bool)> = Vec::new(); // (block_id, set_inherit)
        for block in blocks.iter() {
            if all_flagged.contains(&block.id) {
                // This block has the flag — propagate to successors
                let successors: Vec<u32> = block.next_default.into_iter()
                    .chain(block.next_jumpi.into_iter())
                    .collect();
                for succ_id in successors {
                    updates.push((succ_id, true));
                }
            }
        }

        for (succ_id, set_flag) in updates {
            if let Some(block) = blocks.iter_mut().find(|b| b.id == succ_id) {
                if set_flag && !block.inherit_flags.no_more_sstore {
                    block.inherit_flags.no_more_sstore = true;
                    if let Some(t) = taint_results.get_mut(succ_id as usize) {
                        t.no_more_sstore = true;
                    }
                    changed = true;
                }
            }
        }
    }
}

/// Detect reentrancy patterns
/// Reentrancy = external call (CALL/DELEGATECALL) followed by SSTORE to state
/// that the external call could manipulate via reentrance
fn analyze_reentrancy(
    taint_results: &[BlockTaintResult],
    blocks: &[BasicBlock],
) -> Vec<ReentrancyFinding> {
    let mut findings: Vec<ReentrancyFinding> = Vec::new();

    for (i, taint) in taint_results.iter().enumerate() {
        let block = &blocks[i];

        // Pattern 1: Block has CALL + SSTORE in same block (intra-block reentrancy)
        // The NoMoreSSTORE flag is set by taint analysis when a CALL is seen
        // We need to check that the SSTORE appears AFTER the CALL (by PC)
        if taint.has_call && taint.no_more_sstore {
            // Find the PC of the first CALL instruction
            let call_pcs: Vec<u32> = taint.external_calls.iter()
                .map(|c| c.block_offset) // We don't have direct PC, use block offset
                .collect();
            let _ = call_pcs;

            for op in &taint.storage_ops {
                if op.operation_type == "sstore" {
                    // Check if this SSTORE occurs after a CALL in the instruction stream
                    // We approximate: if there's a CALL in this block and an SSTORE,
                    // check the instruction order
                    for instr in &block.instructions {
                        if instr.opcode.is_call() && op.pc > instr.pc {
                            // SSTORE is after CALL — true reentrancy pattern
                            findings.push(ReentrancyFinding {
                                pattern: "external_call_followed_by_sstore".to_string(),
                                call_offset: block.offset,
                                sstore_offset: Some(block.offset),
                                call_value_tainted: taint.external_calls.iter()
                                    .any(|c| c.value_tainted),
                                has_guard: false,
                                risk: if op.tainted { "high".to_string() } else { "medium".to_string() },
                                block_id: block.id,
                                details: format!(
                                    "External call ({} {}) at pc {} followed by SSTORE to slot 0x{:x} \
                                     at pc {} in the same block. No reentrancy guard detected. SSTORE \
                                     occurs after CALL, allowing reentrant calls to manipulate state \
                                     before it is updated. SSTORE slot tainted: {}.",
                                    taint.external_calls.first().map(|c| c.call_type.as_str()).unwrap_or("?"),
                                    taint.external_calls.first().and_then(|c| c.target_address.as_deref()).unwrap_or("unknown"),
                                    block.instructions.iter().find(|i| i.opcode.is_call()).map(|i| i.pc).unwrap_or(0),
                                    op.slot,
                                    op.pc,
                                    op.tainted
                                ),
                            });
                            break; // Only report once per SSTORE
                        }
                    }
                }
            }
        }

        // Pattern 2: Inherit flag from predecessor + SSTORE (cross-block reentrancy)
        if block.inherit_flags.no_more_sstore {
            for op in &taint.storage_ops {
                if op.operation_type == "sstore" {
                    findings.push(ReentrancyFinding {
                        pattern: "external_call_in_predecessor_then_sstore".to_string(),
                        call_offset: block.offset,
                        sstore_offset: Some(block.offset),
                        call_value_tainted: false,
                        has_guard: false,
                        risk: if op.tainted { "high".to_string() } else { "medium".to_string() },
                        block_id: block.id,
                        details: format!(
                            "Block {} has NoMoreSSTORE inherited from predecessor \
                             (external call was made in a prior block) and then performs \
                             an SSTORE to slot 0x{:x}. This pattern suggests state updates \
                             happen after external calls without proper reentrancy guards. \
                             SSTORE slot tainted: {}.",
                            block.offset,
                            op.slot,
                            op.tainted
                        ),
                    });
                }
            }
        }

        // Pattern 3: Tainted external call to unknown address followed by state change
        // This is the classic "checks-effects-interactions" violation
        if taint.has_call {
            let risky_calls: Vec<_> = taint.external_calls.iter()
                .filter(|c| c.target_tainted || c.reentrancy_risk == "high" || c.reentrancy_risk == "medium")
                .collect();

            if !risky_calls.is_empty() && !taint.storage_ops.is_empty() {
                let has_sstore_after = true; // SSTORE in same block as CALL = reentrancy risk
                if has_sstore_after {
                    findings.push(ReentrancyFinding {
                        pattern: "checks_effects_interactions_violation".to_string(),
                        call_offset: block.offset,
                        sstore_offset: Some(block.offset),
                        call_value_tainted: risky_calls.iter().any(|c| c.value_tainted),
                        has_guard: false,
                        risk: "high".to_string(),
                        block_id: block.id,
                        details: format!(
                            "Potential checks-effects-interactions violation: \
                             external call ({} {}) with {} risky call(s) in the same \
                             block as {} SSTORE operation(s). State is modified after \
                             external call, which can be exploited via reentrancy.",
                            risky_calls.first().map(|c| c.call_type.as_str()).unwrap_or("?"),
                            risky_calls.first().and_then(|c| c.target_address.as_deref()).unwrap_or("unknown"),
                            risky_calls.len(),
                            taint.storage_ops.iter().filter(|o| o.operation_type == "sstore").count()
                        ),
                    });
                }
            }
        }
    }

    // Pattern 4: Cross-block reentrancy — CALL in one block, SSTORE in a successor
    // without a guard check in between
    for (i, taint) in taint_results.iter().enumerate() {
        let block = &blocks[i];
        if taint.has_call {
            // Check successors for SSTORE without reentrancy guard
            for &succ_id in block.next_default.as_ref().into_iter().chain(block.next_jumpi.as_ref().into_iter()) {
                if let Some(succ_taint) = taint_results.get(succ_id as usize) {
                    // Check if successor has an SSTORE and the call wasn't to a known safe address
                    let has_unsafe_sstore = succ_taint.storage_ops.iter().any(|op| {
                        op.operation_type == "sstore" && !succ_taint.no_more_sstore
                    });
                    if has_unsafe_sstore {
                        // Check if there's a guard check (SLOAD before SSTORE)
                        let has_guard = succ_taint.storage_ops.iter().any(|op| {
                            op.operation_type == "sload"
                        });
                        if !has_guard {
                            findings.push(ReentrancyFinding {
                                pattern: "cross_block_reentrancy".to_string(),
                                call_offset: block.offset,
                                sstore_offset: Some(succ_taint.block_id),
                                call_value_tainted: false,
                                has_guard: false,
                                risk: "medium".to_string(),
                                block_id: succ_id,
                                details: format!(
                                    "External call in block {} followed by SSTORE in successor block {}. \
                                     No guard check (SLOAD) detected between call and state modification. \
                                     This pattern allows reentrant calls to modify state mid-execution.",
                                    block.offset,
                                    succ_id
                                ),
                            });
                        }
                    }
                }
            }
        }
    }

    findings.dedup_by(|a, b| a.pattern == b.pattern && a.block_id == b.block_id);
    findings
}

/// Infer invariant candidates from storage access patterns
fn infer_invariants(
    storage_analysis: &[StorageSlotAnalysis],
    taint_results: &[BlockTaintResult],
) -> Vec<InvariantCandidate> {
    let mut invariants: Vec<InvariantCandidate> = Vec::new();

    // Pattern 1: totalSupply + balance slots written together
    let total_supply_slot = storage_analysis.iter()
        .find(|s| s.label.as_deref() == Some("totalSupply_or_owner") || s.slot == "0x0")
        .map(|s| s.slot_u64);

    let balance_slots: Vec<&StorageSlotAnalysis> = storage_analysis.iter()
        .filter(|s| s.label.as_deref() == Some("balance_mapping"))
        .collect();

    if let Some(ts_slot) = total_supply_slot {
        if !balance_slots.is_empty() {
            invariants.push(InvariantCandidate {
                expression: "sum(balances) == totalSupply".to_string(),
                slots: storage_analysis.iter()
                    .map(|s| s.slot.clone())
                    .collect(),
                confidence: 0.85,
                rationale: "totalSupply slot (0x0) is written alongside multiple balance mapping slots, \
                            suggesting an ERC20-style invariant where the sum of all user balances \
                            must equal the total supply.".to_string(),
                supporting_evidence: vec![
                    format!("Slot 0x{:x} written as totalSupply", ts_slot),
                    format!("{} balance slots correlate with totalSupply writes", balance_slots.len()),
                ],
            });
        }
    }

    // Pattern 2: ETH balance invariant
    // If ADDRESS balance is checked before CALL, or CALL value is tracked
    let eth_balance_pattern = taint_results.iter()
        .any(|t| {
            t.external_calls.iter().any(|c| c.value_tainted)
        });

    if eth_balance_pattern {
        invariants.push(InvariantCandidate {
            expression: "contractBalance >= sumOfOutstandingWithdrawals".to_string(),
            slots: vec!["0x0".to_string()],
            confidence: 0.70,
            rationale: "External calls with tainted msg.value detected. The contract's ETH balance \
                        must always be >= the sum of withdrawals tracked in storage, otherwise \
                        a withdraw-more-than-balance vulnerability exists.".to_string(),
            supporting_evidence: vec![
                "Tainted ETH value transferred in external call".to_string(),
                "Potential ETH balance invariant".to_string(),
            ],
        });
    }

    // Pattern 3: Co-written slots (state coupling)
    for slot_a in storage_analysis {
        for co_slot in &slot_a.always_written_with {
            if let Some(slot_b) = storage_analysis.iter().find(|s| s.slot == *co_slot) {
                invariants.push(InvariantCandidate {
                    expression: format!(
                        "slot({}) == slot({}) + delta",
                        slot_a.slot_u64, slot_b.slot_u64
                    ),
                    slots: vec![slot_a.slot.clone(), slot_b.slot.clone()],
                    confidence: 0.60,
                    rationale: format!(
                        "Slots 0x{:x} and 0x{:x} are always written together in the same block, \
                         indicating a state coupling relationship that must hold invariant.",
                        slot_a.slot_u64, slot_b.slot_u64
                    ),
                    supporting_evidence: vec![
                        format!("Co-written in same block: 0x{:x} ↔ 0x{:x}",
                            slot_a.slot_u64, slot_b.slot_u64),
                    ],
                });
            }
        }
    }

    invariants
}

/// Detect high-level control flow structures (if/else, while, for)
fn detect_control_flow(blocks: &[BasicBlock]) -> Vec<ControlFlowStructure> {
    let mut structures: Vec<ControlFlowStructure> = Vec::new();

    for block in blocks {
        // Check for if/else: conditional jump with fallthrough
        if block.next_jumpi.is_some() && block.next_default.is_some() {
            // Check if both branches eventually merge
            let jumpi_target = block.next_jumpi.unwrap();
            let fallthrough = block.next_default.unwrap();

            let merge_point = find_merge_point(blocks, jumpi_target, fallthrough);
            if let Some(merge) = merge_point {
                // Check what's in the conditional block
                let condition_block = blocks.iter().find(|b| b.id == jumpi_target);
                structures.push(ControlFlowStructure {
                    offset: block.offset,
                    structure_type: "if".to_string(),
                    condition: Some(format!(
                        "block {} -> block {} (conditional) with merge at block {}",
                        block.id, jumpi_target, merge
                    )),
                    block_range: [block.id, merge],
                });
            }
        }

        // Check for while/for loops (back edges): a block is a loop header
        // if it dominates one of its own predecessors
        if block.dominators.iter().any(|&d| d == block.id) && block.id != blocks.first().map(|b| b.id).unwrap_or(0) {
            // Check if any predecessor is also dominated by this block (back edge)
            for (pred_id, _) in &block.references {
                if block.dominators.contains(pred_id) {
                    structures.push(ControlFlowStructure {
                        offset: block.offset,
                        structure_type: "loop".to_string(),
                        condition: Some(format!(
                            "Loop header at block {} — back edge from block {} (predecessor dominated by this block)",
                            block.id, pred_id
                        )),
                        block_range: [block.id, *pred_id],
                    });
                    break;
                }
            }
        }
    }

    structures
}

fn find_merge_point(blocks: &[BasicBlock], target_a: u32, target_b: u32) -> Option<u32> {
    // Find a common successor between the two branches
    let block_a = blocks.iter().find(|b| b.id == target_a)?;
    let block_b = blocks.iter().find(|b| b.id == target_b)?;

    // Check for common successor
    let succ_a: std::collections::HashSet<u32> = block_a.next_default
        .into_iter().chain(block_a.next_jumpi.into_iter())
        .collect();
    let succ_b: std::collections::HashSet<u32> = block_b.next_default
        .into_iter().chain(block_b.next_jumpi.into_iter())
        .collect();

    let common = succ_a.intersection(&succ_b).next().copied();
    common.or(Some(blocks.last()?.id))
}

/// Convert BasicBlocks + taint results to serializable BlockInfo
fn info_blocks(
    blocks: &[BasicBlock],
    taint_results: &[BlockTaintResult],
) -> Vec<BlockInfo> {
    blocks.iter().enumerate().map(|(i, block)| {
        let taint = &taint_results[i];

        let flags: Vec<String> = {
            let mut f = Vec::new();
            if block.flags.no_more_sstore { f.push("no_more_sstore".to_string()); }
            if block.inherit_flags.no_more_sstore { f.push("inherited_no_more_sstore".to_string()); }
            if taint.has_call { f.push("has_external_call".to_string()); }
            f
        };

        let calls: Vec<ExternalCallInfo> = taint.external_calls.iter().map(|c| ExternalCallInfo {
            call_type: c.call_type.clone(),
            target: c.target_address.clone(),
            target_tainted: c.target_tainted,
            value: None,
            value_tainted: c.value_tainted,
            reentrancy_risk: c.reentrancy_risk.clone(),
        }).collect();

        let instructions: Vec<InstructionInfo> = block.instructions.iter().map(|instr| {
            InstructionInfo {
                pc: instr.pc,
                opcode: instr.opcode.name().to_string(),
                immediate: if instr.immediate.is_empty() {
                    String::new()
                } else {
                    format!("0x{}", hex::encode(&instr.immediate))
                },
                opcode_byte: {
                    if let Instruction::UNKNOWN(b) = instr.opcode { b }
                    else if let Instruction::INVALID(b) = instr.opcode { b }
                    else { 0 }
                },
            }
        }).collect();

        BlockInfo {
            id: block.id,
            offset: block.offset,
            size: block.size,
            instructions,
            successors: block.next_default.into_iter()
                .chain(block.next_jumpi.into_iter())
                .collect::<Vec<_>>(),
            predecessors: block.references.iter()
                .map(|(id, _)| *id)
                .collect(),
            flags,
            dominators: block.dominators.clone(),
            calls,
        }
    }).collect()
}
