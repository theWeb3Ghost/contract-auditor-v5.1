/**
 * Solidity Knowledge Base for Porosity-X
 *
 * This module embeds knowledge from the Solidity documentation (v0.8.x) to
 * guide bytecode-level pattern matching and vulnerability detection.
 *
 * Key knowledge encoded:
 * - SOLIDITY_PATTERNS: How Solidity constructs compile to EVM bytecode
 * - SECURITY_PATTERNS: Known vulnerability patterns and their bytecode signatures
 * - ETH_ACCOUNTING: ETH balance invariants that should hold in secure contracts
 * - REENTRANCY_PATTERNS: Reentrancy detection patterns at the bytecode level
 * - ACCESS_CONTROL_PATTERNS: Ownership and access control patterns
 *
 * Source: Solidity v0.8.x documentation (docs.soliditylang.org)
 */

use serde::{Deserialize, Serialize};

/// A Solidity-to-EVM compilation pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidityPattern {
    /// Human-readable name of the pattern
    pub name: String,
    /// What Solidity construct this matches
    pub solidity_construct: String,
    /// EVM bytecode pattern signature
    pub bytecode_pattern: String,
    /// Description of what this pattern represents
    pub description: String,
    /// Risk level if this pattern is found in a dangerous context
    pub risk_level: String,
}

/// All known Solidity-to-EVM compilation patterns
pub fn solidity_patterns() -> Vec<SolidityPattern> {
    vec![
        // --- msg.value patterns ---
        // In Solidity, `require(msg.value > 0)` compiles to:
        //   CALLVALUE ISZERO PUSH2(revert_offset) JUMPI
        // The ISZERO returns 1 (true) when msg.value == 0, and JUMPI jumps
        // to the revert block. An inverted check would jump to function body instead.
        SolidityPattern {
            name: "require_msg_value_gt_zero".to_string(),
            solidity_construct: "require(msg.value > 0)".to_string(),
            bytecode_pattern: "CALLVALUE ISZERO PUSH2(revert_offset) JUMPI".to_string(),
            description: "Standard Solidity guard: require msg.value > 0. The JUMPI jumps to REVERT when msg.value == 0 (ISZERO returns true).".to_string(),
            risk_level: "none".to_string(),
        },
        SolidityPattern {
            name: "require_msg_value_eq_amount".to_string(),
            solidity_construct: "require(msg.value == price)".to_string(),
            bytecode_pattern: "CALLVALUE PUSH2(price) EQ PUSH2(revert_offset) JUMPI".to_string(),
            description: "Requires exact ETH amount. msg.value compared to price via EQ, then JUMPI to revert on mismatch.".to_string(),
            risk_level: "none".to_string(),
        },
        SolidityPattern {
            name: "inverted_msg_value_check".to_string(),
            solidity_construct: "Conditional branch without msg.value enforcement".to_string(),
            bytecode_pattern: "CALLVALUE ISZERO PUSH2(func_body) JUMPI".to_string(),
            description: "INVERTED CHECK: When msg.value == 0 (ISZERO true), JUMPI jumps to function body (not REVERT). Allows calling with 0 ETH.".to_string(),
            risk_level: "critical".to_string(),
        },
        SolidityPattern {
            name: "if_else_eth_branch".to_string(),
            solidity_construct: "if (condition) { ... payable ... } else { ... }".to_string(),
            bytecode_pattern: "CALLVALUE ... JUMPI (conditional) ... JUMPI (value check)".to_string(),
            description: "If/else with ETH transfer in one branch but not the other. The else branch may not enforce msg.value.".to_string(),
            risk_level: "high".to_string(),
        },

        // --- Function dispatch patterns ---
        // Solidity's dispatcher: PUSH4(selector) AND DUP1 PUSH4(sel) EQ JUMPI
        // (The AND masks the first 4 bytes of the selector from calldata)
        SolidityPattern {
            name: "selector_dispatch".to_string(),
            solidity_construct: "Function dispatch table".to_string(),
            bytecode_pattern: "PUSH4(selector) EQ PUSH2(entry) JUMPI".to_string(),
            description: "Standard Solidity dispatcher: compares first 4 bytes of calldata against selector, JUMPI to function entry if matched.".to_string(),
            risk_level: "none".to_string(),
        },
        SolidityPattern {
            name: "fallback_function".to_string(),
            solidity_construct: "fallback() external payable".to_string(),
            bytecode_pattern: "CALLVALUE JUMP (no selector match)".to_string(),
            description: "Fallback function: called when no selector matches. Often payable.".to_string(),
            risk_level: "low".to_string(),
        },

        // --- Storage patterns ---
        // ERC20 pattern: slot 0 = totalSupply, slot 1 = owner, mapping at slot 2+
        SolidityPattern {
            name: "total_supply_slot_0".to_string(),
            solidity_construct: "uint256 public totalSupply".to_string(),
            bytecode_pattern: "SSTORE(slot=0)".to_string(),
            description: "Total supply stored in slot 0. Common in ERC20 tokens.".to_string(),
            risk_level: "none".to_string(),
        },
        SolidityPattern {
            name: "balance_mapping".to_string(),
            solidity_construct: "mapping(address => uint256) private _balances".to_string(),
            bytecode_pattern: "SLOAD SSTORE (after keccak256 of sender + offset)".to_string(),
            description: "Balance mapping: typically uses keccak256(0xb3ded43f + address) for ERC20-style balance slots.".to_string(),
            risk_level: "none".to_string(),
        },
        SolidityPattern {
            name: "checks_effects_interactions".to_string(),
            solidity_construct: "Checks-Effects-Interactions pattern".to_string(),
            bytecode_pattern: "SLOAD/SSTORE ... CALL ... SSTORE".to_string(),
            description: "Secure pattern: state updates before external calls. Violation = reentrancy risk.".to_string(),
            risk_level: "none".to_string(),
        },
        SolidityPattern {
            name: "vulnerable_reentrancy".to_string(),
            solidity_construct: "No state update before external call".to_string(),
            bytecode_pattern: "CALL ... SSTORE (without prior SSTORE in same block)".to_string(),
            description: "VULNERABLE: External call before state update enables reentrancy. Missing checks-effects-interactions.".to_string(),
            risk_level: "critical".to_string(),
        },

        // --- ETH transfer patterns ---
        SolidityPattern {
            name: "call_value_transfer".to_string(),
            solidity_construct: "addr.call{value: amount}(\"\")".to_string(),
            bytecode_pattern: "PUSH(gas) PUSH(addr) PUSH(value) ... CALL".to_string(),
            description: "ETH transfer via call with value. msg.value forwarded.".to_string(),
            risk_level: "none".to_string(),
        },
        SolidityPattern {
            name: "withdraw_pattern".to_string(),
            solidity_construct: "function withdraw() public".to_string(),
            bytecode_pattern: "SLOAD(balance) SSTORE(0) CALL(value=balance)".to_string(),
            description: "Withdraw pattern: read balance, zero it, transfer ETH. Must update state BEFORE the call.".to_string(),
            risk_level: "medium".to_string(),
        },
        SolidityPattern {
            name: "unrestricted_write_withdraw".to_string(),
            solidity_construct: "function setPrice(...) without require(msg.value > 0)".to_string(),
            bytecode_pattern: "PUSH2(target) JUMP (no msg.value requirement)".to_string(),
            description: "State write (SSTORE for price/fee) without requiring msg.value. Attacker can set price to 0, then withdraw later.".to_string(),
            risk_level: "critical".to_string(),
        },

        // --- Access control patterns ---
        SolidityPattern {
            name: "only_owner_check".to_string(),
            solidity_construct: "modifier onlyOwner".to_string(),
            bytecode_pattern: "CALLER PUSH2(owner_slot) SLOAD EQ PUSH2(revert) JUMPI".to_string(),
            description: "Access control: checks if caller equals stored owner.".to_string(),
            risk_level: "none".to_string(),
        },
        SolidityPattern {
            name: "no_access_control".to_string(),
            solidity_construct: "function without onlyOwner modifier".to_string(),
            bytecode_pattern: "JUMPDEST (no CALLER SLOAD EQ check)".to_string(),
            description: "No access control detected. Any address can call this function.".to_string(),
            risk_level: "high".to_string(),
        },
    ]
}

/// Invariant patterns that should hold in secure Solidity contracts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantPattern {
    pub name: String,
    pub expression: String,
    pub confidence: f32,
    pub when_applicable: String,
}

/// ETH accounting invariants from Solidity semantics
pub fn eth_invariants() -> Vec<InvariantPattern> {
    vec![
        InvariantPattern {
            name: "total_supply_conservation".to_string(),
            expression: "sum(balances) == totalSupply".to_string(),
            confidence: 0.95,
            when_applicable: "Any contract with a totalSupply slot (slot 0) and balance mapping slots".to_string(),
        },
        InvariantPattern {
            name: "eth_balance_conservation".to_string(),
            expression: "address(this).balance == sum(deposits) - sum(withdrawals)".to_string(),
            confidence: 0.90,
            when_applicable: "Any payable contract that accepts or sends ETH".to_string(),
        },
        InvariantPattern {
            name: "withdraw_limit_check".to_string(),
            expression: "amount_to_withdraw <= user_balance".to_string(),
            confidence: 0.85,
            when_applicable: "Any withdraw function that takes an amount parameter".to_string(),
        },
        InvariantPattern {
            name: "price_fee_paid_before_set".to_string(),
            expression: "fee > 0 and msg.value >= fee whenever setPriceFeeEth succeeds".to_string(),
            confidence: 0.80,
            when_applicable: "Functions that set price/fee storage and are payable".to_string(),
        },
    ]
}

/// Reentrancy-specific patterns from Solidity documentation
pub fn reentrancy_patterns() -> Vec<SolidityPattern> {
    vec![
        SolidityPattern {
            name: "checks_effects_interactions_good".to_string(),
            solidity_construct: "Checks-Effects-Interactions".to_string(),
            bytecode_pattern: "require checks -> SSTORE(state updates) -> external CALL".to_string(),
            description: "Secure: all checks done, all state updated BEFORE external call. Prevents reentrancy.".to_string(),
            risk_level: "none".to_string(),
        },
        SolidityPattern {
            name: "checks_effects_interactions_bad".to_string(),
            solidity_construct: "Interactions before Effects".to_string(),
            bytecode_pattern: "external CALL -> SSTORE".to_string(),
            description: "VULNERABLE: External call happens before state update. Reentrant calls can double-withdraw or manipulate state.".to_string(),
            risk_level: "critical".to_string(),
        },
        SolidityPattern {
            name: "reentrancy_guard".to_string(),
            solidity_construct: "nonReentrant modifier or bool locked".to_string(),
            bytecode_pattern: "_reentrantKey ISZERO PUSH2(revert) JUMPI ... SSTORE(locked=1) ... SSTORE(locked=0)".to_string(),
            description: "Reentrancy guard: uses a storage slot as mutex. Set before external call, cleared after.".to_string(),
            risk_level: "none".to_string(),
        },
        SolidityPattern {
            name: "no_reentrancy_guard".to_string(),
            solidity_construct: "function with external CALL but no mutex".to_string(),
            bytecode_pattern: "CALL (no preceding SSTORE to known guard slot)".to_string(),
            description: "No reentrancy guard detected. If state is modified after the call, reentrancy is possible.".to_string(),
            risk_level: "high".to_string(),
        },
    ]
}
