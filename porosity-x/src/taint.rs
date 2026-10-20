use crate::disasm::{DecodedInstruction, Instruction};
use crate::blocks::BasicBlock;
use std::collections::HashMap;

/// Stack register types — ported from Porosity's StackRegisterType enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum StackRegisterType {
    NumValueDefault = 0,
    Constant = (1 << 1),
    ConstantComputed = (1 << 2),
    RegTypeLabel = (1 << 3),
    RegTypeLabelCaller = (1 << 4),    // msg.sender
    RegTypeLabelBlockHash = (1 << 5),
    RegTypeTypeFlag = (1 << 6),
    RegTypeLabelSha3 = (1 << 7),
    UserInput = (1 << 8),              // calldata
    UserInputTainted = (1 << 9),        // msg.value, msg.sender, this
    StorageType = (1 << 10),
    GasLimit = (1 << 11),
    CallReturnStatus = (1 << 12),
    AddressType = (1 << 13),
    RegTypeLabelThis = (1 << 14),      // this
}

impl StackRegisterType {
    /// Check if this type carries taint (user input or derived from it)
    pub fn is_tainted(&self) -> bool {
        let bits = *self as u32;
        bits & (StackRegisterType::UserInput as u32 | StackRegisterType::UserInputTainted as u32) != 0
    }

    /// Check if this is an external environment input
    pub fn is_environmental(&self) -> bool {
        let bits = *self as u32;
        bits & (StackRegisterType::UserInput as u32 | StackRegisterType::UserInputTainted as u32 | StackRegisterType::GasLimit as u32) != 0
    }

    pub fn from_bits(bits: u32) -> StackRegisterType {
        // Return the closest matching type for a combined bitmask
        // This is used when taint propagates through operations
        if bits & StackRegisterType::UserInput as u32 != 0 {
            return StackRegisterType::UserInput;
        }
        if bits & StackRegisterType::UserInputTainted as u32 != 0 {
            return StackRegisterType::UserInputTainted;
        }
        if bits & StackRegisterType::StorageType as u32 != 0 {
            return StackRegisterType::StorageType;
        }
        if bits & StackRegisterType::Constant as u32 != 0 {
            return StackRegisterType::Constant;
        }
        StackRegisterType::NumValueDefault
    }
}

/// A symbolic stack register — tracks taint and semantic meaning
#[derive(Debug, Clone)]
pub struct StackRegister {
    pub name: String,
    pub exp: String,  // pseudocode expression
    pub reg_type: StackRegisterType,
    pub value: Option<u64>,  // concrete value if constant
    pub offset: u32,
    pub last_modification_pc: u32,
}

impl StackRegister {
    pub fn new(reg_type: StackRegisterType, name: String, exp: String) -> Self {
        StackRegister {
            name,
            exp,
            reg_type,
            value: None,
            offset: 0,
            last_modification_pc: 0,
        }
    }

    pub fn constant(value: u64) -> Self {
        StackRegister {
            name: format!("0x{:x}", value),
            exp: format!("{}", value),
            reg_type: StackRegisterType::Constant,
            value: Some(value),
            offset: 0,
            last_modification_pc: 0,
        }
    }

    pub fn calldata(offset: u32) -> Self {
        StackRegister {
            name: "calldata".to_string(),
            exp: format!("calldata[{}]", offset),
            reg_type: StackRegisterType::UserInput,
            value: None,
            offset,
            last_modification_pc: 0,
        }
    }

    pub fn caller() -> Self {
        StackRegister {
            name: "msg.sender".to_string(),
            exp: "caller()".to_string(),
            reg_type: StackRegisterType::UserInputTainted,
            value: None,
            offset: 0,
            last_modification_pc: 0,
        }
    }

    pub fn callvalue() -> Self {
        StackRegister {
            name: "msg.value".to_string(),
            exp: "callvalue".to_string(),
            reg_type: StackRegisterType::UserInputTainted,
            value: None,
            offset: 0,
            last_modification_pc: 0,
        }
    }

    pub fn address() -> Self {
        StackRegister {
            name: "this".to_string(),
            exp: "address".to_string(),
            reg_type: StackRegisterType::from_bits(
                StackRegisterType::AddressType as u32 | StackRegisterType::UserInputTainted as u32
            ),
            value: None,
            offset: 0,
            last_modification_pc: 0,
        }
    }

    /// Combine taint from two registers (e.g., a + b)
    pub fn combine_taint(&self, other: &StackRegister) -> StackRegisterType {
        let combined = (self.reg_type as u32) | (other.reg_type as u32);
        StackRegisterType::from_bits(combined)
    }

    /// Check if this register's value is tainted
    pub fn is_tainted(&self) -> bool {
        self.reg_type.is_tainted()
    }

    /// Mark as tainted
    pub fn taint(&mut self) {
        self.reg_type = StackRegisterType::UserInputTainted;
    }
}

/// External call recorded during taint tracking
#[derive(Debug, Clone)]
pub struct ExternalCall {
    pub block_offset: u32,
    pub call_type: String,  // CALL, DELEGATECALL, STATICCALL, CALLCODE
    pub target_tainted: bool,
    pub value_tainted: bool,
    pub target_known: bool,   // is the target a constant address?
    pub target_address: Option<String>,  // hex address if known
    pub gas_tainted: bool,
    pub function_selector: Option<String>,  // if calldata contains a known selector
    pub caller_function: Option<String>,   // selector of the enclosing function
    pub reentrancy_risk: String,  // "low", "medium", "high", "unknown"
    pub has_reentrancy_guard: bool,  // does an SLOAD from known guard slot precede?
}

/// Storage operation recorded during taint tracking
#[derive(Debug, Clone)]
pub struct StorageOperation {
    pub slot: u64,
    pub operation_type: String,  // "sload" or "sstore"
    pub block_offset: u32,
    pub pc: u32,
    pub tainted: bool,     // does this op involve user input?
    pub label: Option<String>,  // semantic label if identifiable
}

/// A taint analysis result for a single basic block
#[derive(Debug, Clone)]
pub struct BlockTaintResult {
    pub block_id: u32,
    pub final_stack: Vec<StackRegister>,
    pub external_calls: Vec<ExternalCall>,
    pub storage_ops: Vec<StorageOperation>,
    pub taint_sources: Vec<TaintSource>,
    pub has_call: bool,          // CALL/DELEGATECALL/STATICCALL seen
    pub no_more_sstore: bool,    // reentrancy flag set
}

/// A detected taint source
#[derive(Debug, Clone)]
pub struct TaintSource {
    pub source_type: String,  // "msg.sender", "msg.value", "calldata", "environmental"
    pub description: String,
    pub block_offset: u32,
    pub pc: u32,
    pub slot_or_offset: Option<u32>,
}

/// Full program-level taint analysis
#[derive(Debug, Default)]
pub struct TaintAnalysis {
    pub block_results: Vec<BlockTaintResult>,
    pub all_taint_sources: Vec<TaintSource>,
    pub all_external_calls: Vec<ExternalCall>,
    pub all_storage_ops: Vec<StorageOperation>,
    pub function_taint: HashMap<String, Vec<TaintSource>>,  // selector -> sources
}

/// Execute symbolic taint analysis on a single basic block
/// This is a port of VMState::executeInstruction with stack tracking
pub fn analyze_block_taint(block: &BasicBlock) -> BlockTaintResult {
    let mut stack: Vec<StackRegister> = Vec::new();
    let mut external_calls: Vec<ExternalCall> = Vec::new();
    let mut storage_ops: Vec<StorageOperation> = Vec::new();
    let mut taint_sources: Vec<TaintSource> = Vec::new();
    let mut has_call = false;
    let mut no_more_sstore = false;

    for instr in &block.instructions {
        execute_instruction(
            instr,
            &mut stack,
            &mut external_calls,
            &mut storage_ops,
            &mut taint_sources,
            &mut has_call,
            &mut no_more_sstore,
            block.offset,
        );
    }

    // Inherit the NoMoreSSTORE flag from block flags (if a CALL was seen in a
    // predecessor block, this block inherits the flag — reentrancy pattern)
    if block.inherit_flags.no_more_sstore {
        no_more_sstore = true;
    }

    BlockTaintResult {
        block_id: block.id,
        final_stack: stack,
        external_calls,
        storage_ops,
        taint_sources,
        has_call,
        no_more_sstore,
    }
}

fn execute_instruction(
    instr: &DecodedInstruction,
    stack: &mut Vec<StackRegister>,
    external_calls: &mut Vec<ExternalCall>,
    storage_ops: &mut Vec<StorageOperation>,
    taint_sources: &mut Vec<TaintSource>,
    has_call: &mut bool,
    no_more_sstore: &mut bool,
    block_offset: u32,
) {
    let opcode = &instr.opcode;

    // Handle PUSH instructions first
    if let Instruction::UNKNOWN(b) = opcode {
        if (0x60..=0x7f).contains(b) && !instr.immediate.is_empty() {
            let value = parse_push_value(&instr.immediate);
            stack.push(StackRegister::constant(value));
            return;
        }
    }

    match opcode {
        // === TAINT SOURCES ===

        Instruction::CALLDATALOAD => {
            // Pops: offset, pushes: value
            let offset_reg = stack.pop();
            let offset = if let Some(ref r) = offset_reg {
                r.value.unwrap_or(0)
            } else {
                0
            };

            let mut reg = StackRegister::calldata(offset as u32);
            reg.last_modification_pc = instr.pc;
            stack.push(reg);

            taint_sources.push(TaintSource {
                source_type: "calldata".to_string(),
                description: format!("calldata[{}]", offset),
                block_offset,
                pc: instr.pc,
                slot_or_offset: Some(offset as u32),
            });
        }

        Instruction::CALLER => {
            let mut reg = StackRegister::caller();
            reg.last_modification_pc = instr.pc;
            stack.push(reg);

            taint_sources.push(TaintSource {
                source_type: "msg.sender".to_string(),
                description: "caller()".to_string(),
                block_offset,
                pc: instr.pc,
                slot_or_offset: None,
            });
        }

        Instruction::CALLVALUE => {
            let mut reg = StackRegister::callvalue();
            reg.last_modification_pc = instr.pc;
            stack.push(reg);

            taint_sources.push(TaintSource {
                source_type: "msg.value".to_string(),
                description: "callvalue".to_string(),
                block_offset,
                pc: instr.pc,
                slot_or_offset: None,
            });
        }

        Instruction::ADDRESS => {
            let mut reg = StackRegister::address();
            reg.last_modification_pc = instr.pc;
            stack.push(reg);
        }

        Instruction::ORIGIN => {
            let reg = StackRegister {
                name: "tx.origin".to_string(),
                exp: "origin".to_string(),
                reg_type: StackRegisterType::UserInputTainted,
                value: None,
                offset: 0,
                last_modification_pc: instr.pc,
            };
            stack.push(reg);

            taint_sources.push(TaintSource {
                source_type: "tx.origin".to_string(),
                description: "origin".to_string(),
                block_offset,
                pc: instr.pc,
                slot_or_offset: None,
            });
        }

        Instruction::BLOCKHASH
        | Instruction::TIMESTAMP
        | Instruction::NUMBER
        | Instruction::DIFFICULTY
        | Instruction::GASLIMIT
        | Instruction::COINBASE
        | Instruction::GASPRICE => {
            let name = format!("{:?}", opcode);
            let reg = StackRegister {
                name: name.clone(),
                exp: name.clone(),
                reg_type: StackRegisterType::UserInputTainted,
                value: None,
                offset: 0,
                last_modification_pc: instr.pc,
            };
            stack.push(reg);

            taint_sources.push(TaintSource {
                source_type: "environmental".to_string(),
                description: name,
                block_offset,
                pc: instr.pc,
                slot_or_offset: None,
            });
        }

        // === STORAGE ===

        Instruction::SLOAD => {
            let slot_reg = stack.pop();

            let slot_val = slot_reg.as_ref().and_then(|r| r.value).unwrap_or(0);
            let slot_tainted = slot_reg.as_ref().map(|r| r.is_tainted()).unwrap_or(false);

            let mut reg = StackRegister {
                name: format!("storage[{}]", slot_val),
                exp: format!("storage[{}]", slot_val),
                reg_type: StackRegisterType::StorageType,
                value: slot_reg.as_ref().and_then(|r| r.value),
                offset: slot_reg.as_ref().map(|r| r.offset).unwrap_or(0),
                last_modification_pc: instr.pc,
            };

            // If the slot itself is tainted, the result is tainted
            if slot_tainted {
                reg.taint();
            }

            stack.push(reg);

            storage_ops.push(StorageOperation {
                slot: slot_val,
                operation_type: "sload".to_string(),
                block_offset,
                pc: instr.pc,
                tainted: slot_tainted,
                label: None,
            });
        }

        Instruction::SSTORE => {
            // SSTORE pops: (slot), (value)
            let value_reg = stack.pop();
            let slot_reg = stack.pop();

            let slot_val = slot_reg.as_ref().and_then(|r| r.value).unwrap_or(0);
            let value_tainted = value_reg.as_ref().map(|r| r.is_tainted()).unwrap_or(false);
            let slot_tainted = slot_reg.as_ref().map(|r| r.is_tainted()).unwrap_or(false);

            storage_ops.push(StorageOperation {
                slot: slot_val,
                operation_type: "sstore".to_string(),
                block_offset,
                pc: instr.pc,
                tainted: value_tainted || slot_tainted,
                label: None,
            });
        }

        // === EXTERNAL CALLS ===

        Instruction::CALL => {
            // CALL: pops (gas, addr, value, argsOffset, argsSize, retOffset, retSize)
            // Stack order (top to bottom): retSize, retOffset, argsSize, argsOffset, value, addr, gas
            let ret_size = stack.pop();
            let ret_offset = stack.pop();
            let args_size = stack.pop();
            let args_offset = stack.pop();
            let value = stack.pop();
            let addr = stack.pop();
            let gas = stack.pop();

            *has_call = true;
            *no_more_sstore = true; // Set reentrancy guard flag

            let target_tainted = addr.as_ref().map(|r| r.is_tainted()).unwrap_or(false);
            let value_tainted = value.as_ref().map(|r| r.is_tainted()).unwrap_or(false);
            let gas_tainted = gas.as_ref().map(|r| r.is_tainted()).unwrap_or(false);
            let target_address = addr.as_ref().and_then(|r| r.value.map(|v| format!("0x{:x}", v)));

            let mut call = ExternalCall {
                block_offset,
                call_type: "CALL".to_string(),
                target_tainted,
                value_tainted,
                target_known: addr.as_ref().map(|r| r.value.is_some()).unwrap_or(false),
                target_address: target_address.clone(),
                gas_tainted,
                function_selector: None,
                caller_function: None,
                reentrancy_risk: "unknown".to_string(),
                has_reentrancy_guard: false,
            };

            // Determine reentrancy risk
            if target_tainted {
                call.reentrancy_risk = "high".to_string();
            } else if value_tainted {
                call.reentrancy_risk = "medium".to_string();
            } else {
                call.reentrancy_risk = "low".to_string();
            }

            external_calls.push(call);

            // CALL pushes return status (0 or 1)
            stack.push(StackRegister {
                name: "call_retval".to_string(),
                exp: "call()".to_string(),
                reg_type: StackRegisterType::CallReturnStatus,
                value: None,
                offset: 0,
                last_modification_pc: instr.pc,
            });
        }

        Instruction::CALLCODE => {
            // CALLCODE: similar to CALL
            let _ret_size = stack.pop();
            let _ret_offset = stack.pop();
            let _args_size = stack.pop();
            let _args_offset = stack.pop();
            let value = stack.pop();
            let addr = stack.pop();
            let gas = stack.pop();

            *has_call = true;
            *no_more_sstore = true;

            let target_tainted = addr.as_ref().map(|r| r.is_tainted()).unwrap_or(false);
            let value_tainted = value.as_ref().map(|r| r.is_tainted()).unwrap_or(false);

            external_calls.push(ExternalCall {
                block_offset,
                call_type: "CALLCODE".to_string(),
                target_tainted,
                value_tainted,
                target_known: addr.as_ref().map(|r| r.value.is_some()).unwrap_or(false),
                target_address: addr.as_ref().and_then(|r| r.value.map(|v| format!("0x{:x}", v))),
                gas_tainted: gas.as_ref().map(|r| r.is_tainted()).unwrap_or(false),
                function_selector: None,
                caller_function: None,
                reentrancy_risk: if target_tainted { "high".to_string() } else { "medium".to_string() },
                has_reentrancy_guard: false,
            });

            stack.push(StackRegister::constant(0)); // return status
        }

        Instruction::DELEGATECALL => {
            // DELEGATECALL: pops (gas, addr, argsOffset, argsSize, retOffset, retSize)
            let _ret_size = stack.pop();
            let _ret_offset = stack.pop();
            let _args_size = stack.pop();
            let _args_offset = stack.pop();
            let addr = stack.pop();
            let gas = stack.pop();

            *has_call = true;
            // DELEGATECALL doesn't set NoMoreSSTORE in the same way —
            // it's the called contract that might reenter, but the current
            // contract's state is modified. We still flag it.

            let target_tainted = addr.as_ref().map(|r| r.is_tainted()).unwrap_or(false);

            let mut call = ExternalCall {
                block_offset,
                call_type: "DELEGATECALL".to_string(),
                target_tainted,
                value_tainted: false, // DELEGATECALL doesn't transfer value
                target_known: addr.as_ref().map(|r| r.value.is_some()).unwrap_or(false),
                target_address: addr.as_ref().and_then(|r| r.value.map(|v| format!("0x{:x}", v))),
                gas_tainted: gas.as_ref().map(|r| r.is_tainted()).unwrap_or(false),
                function_selector: None,
                caller_function: None,
                reentrancy_risk: if target_tainted { "high".to_string() } else { "medium".to_string() },
                has_reentrancy_guard: false,
            };

            external_calls.push(call);

            stack.push(StackRegister {
                name: "delegatecall_retval".to_string(),
                exp: "delegatecall()".to_string(),
                reg_type: StackRegisterType::CallReturnStatus,
                value: None,
                offset: 0,
                last_modification_pc: instr.pc,
            });
        }

        Instruction::STATICCALL => {
            // STATICCALL: pops (gas, addr, argsOffset, argsSize, retOffset, retSize)
            let _ret_size = stack.pop();
            let _ret_offset = stack.pop();
            let _args_size = stack.pop();
            let _args_offset = stack.pop();
            let addr = stack.pop();
            let gas = stack.pop();

            *has_call = true;

            let target_tainted = addr.as_ref().map(|r| r.is_tainted()).unwrap_or(false);

            external_calls.push(ExternalCall {
                block_offset,
                call_type: "STATICCALL".to_string(),
                target_tainted,
                value_tainted: false,
                target_known: addr.as_ref().map(|r| r.value.is_some()).unwrap_or(false),
                target_address: addr.as_ref().and_then(|r| r.value.map(|v| format!("0x{:x}", v))),
                gas_tainted: gas.as_ref().map(|r| r.is_tainted()).unwrap_or(false),
                function_selector: None,
                caller_function: None,
                reentrancy_risk: "low".to_string(), // STATICCALL is read-only
                has_reentrancy_guard: false,
            });

            stack.push(StackRegister::constant(1)); // success
        }

        // === ARITHMETIC & LOGIC (taint propagation) ===

        Instruction::ADD | Instruction::SUB | Instruction::MUL | Instruction::DIV |
        Instruction::SDIV | Instruction::MOD | Instruction::SMOD | Instruction::ADDMOD |
        Instruction::MULMOD | Instruction::EXP | Instruction::SIGNEXTEND |
        Instruction::LT | Instruction::GT | Instruction::SLT | Instruction::SGT |
        Instruction::EQ | Instruction::AND | Instruction::OR | Instruction::XOR => {
            let right = stack.pop();
            let left = stack.pop();

            let mut result_type = StackRegisterType::NumValueDefault;
            let mut exp = String::new();

            if let (Some(l), Some(r)) = (&left, &right) {
                result_type = l.combine_taint(r);
                exp = format!("({} {} {})", l.exp, opcode.name(), r.exp);
            }

            let reg = StackRegister {
                name: format!("{}", opcode.name()),
                exp,
                reg_type: result_type,
                value: None, // Non-constant result (unless both inputs are constant)
                offset: 0,
                last_modification_pc: instr.pc,
            };

            // If both inputs are constant, compute the result
            if let (Some(l), Some(r)) = (&left, &right) {
                if let (Some(lv), Some(rv)) = (l.value, r.value) {
                    let computed = match opcode {
                        Instruction::ADD => lv.wrapping_add(rv),
                        Instruction::SUB => lv.wrapping_sub(rv),
                        _ => 0, // Simplified — full arithmetic is complex
                    };
                    stack.push(StackRegister {
                        name: format!("0x{:x}", computed),
                        exp: format!("0x{:x}", computed),
                        reg_type: StackRegisterType::ConstantComputed,
                        value: Some(computed),
                        offset: 0,
                        last_modification_pc: instr.pc,
                    });
                    return;
                }
            }

            stack.push(reg);
        }

        Instruction::BYTE => {
            let right = stack.pop();
            let left = stack.pop();
            let result_type = left.as_ref()
                .map(|l| l.combine_taint(right.as_ref().unwrap()))
                .unwrap_or(StackRegisterType::NumValueDefault);
            stack.push(StackRegister {
                name: "byte".to_string(),
                exp: format!("byte({}, {})", left.as_ref().map(|l| l.exp.as_str()).unwrap_or("0"), right.as_ref().map(|r| r.exp.as_str()).unwrap_or("0")),
                reg_type: result_type,
                value: None,
                offset: 0,
                last_modification_pc: instr.pc,
            });
        }

        Instruction::ISZERO => {
            let val = stack.pop();
            let result_type = val.as_ref()
                .map(|v| {
                    if v.is_tainted() {
                        StackRegisterType::UserInputTainted
                    } else {
                        StackRegisterType::Constant
                    }
                })
                .unwrap_or(StackRegisterType::Constant);
            stack.push(StackRegister {
                name: "!=".to_string(),
                exp: format!("!={}", val.as_ref().map(|v| v.exp.as_str()).unwrap_or("0")),
                reg_type: result_type,
                value: None,
                offset: 0,
                last_modification_pc: instr.pc,
            });
        }

        Instruction::NOT => {
            let val = stack.pop();
            let result_type = val.as_ref()
                .map(|v| if v.is_tainted() { StackRegisterType::UserInputTainted } else { StackRegisterType::Constant })
                .unwrap_or(StackRegisterType::Constant);
            stack.push(StackRegister {
                name: "!".to_string(),
                exp: format!("~{}", val.as_ref().map(|v| v.exp.as_str()).unwrap_or("0")),
                reg_type: result_type,
                value: None,
                offset: 0,
                last_modification_pc: instr.pc,
            });
        }

        // === SHA3 / KECCAK256 ===
        Instruction::SHA3 => {
            let size = stack.pop();
            let offset = stack.pop();
            // SHA3 result is generally not tainted unless offset/size are
            let tainted = offset.as_ref().map(|r| r.is_tainted()).unwrap_or(false)
                || size.as_ref().map(|r| r.is_tainted()).unwrap_or(false);
            stack.push(StackRegister {
                name: if tainted { "keccak256(tainted)".to_string() } else { "keccak256".to_string() },
                exp: format!("keccak256(mem[{}..{}])",
                    offset.as_ref().map(|r| r.exp.as_str()).unwrap_or("?"),
                    size.as_ref().map(|r| r.exp.as_str()).unwrap_or("?")),
                reg_type: if tainted { StackRegisterType::UserInputTainted } else { StackRegisterType::RegTypeLabelSha3 },
                value: None,
                offset: 0,
                last_modification_pc: instr.pc,
            });
        }

        // === MEMORY ===

        Instruction::MLOAD => {
            let offset = stack.pop();
            let tainted = offset.as_ref().map(|r| r.is_tainted()).unwrap_or(false);
            stack.push(StackRegister {
                name: if tainted { "mem[tainted]".to_string() } else { "mem".to_string() },
                exp: format!("mem[{}]", offset.as_ref().map(|r| r.exp.as_str()).unwrap_or("?")),
                reg_type: if tainted { StackRegisterType::UserInputTainted } else { StackRegisterType::Constant },
                value: None,
                offset: offset.as_ref().and_then(|r| r.value).unwrap_or(0) as u32,
                last_modification_pc: instr.pc,
            });
        }

        Instruction::MSTORE => {
            let value = stack.pop();
            let offset = stack.pop();
            // MSTORE doesn't push anything; it writes to memory
            // We could track memory state, but for now we just consume the args
            let _ = (value, offset);
        }

        Instruction::MSTORE8 => {
            let value = stack.pop();
            let offset = stack.pop();
            let _ = (value, offset);
        }

        // === STACK MANIPULATION ===

        Instruction::POP => {
            if let Some(_) = stack.pop() {
                // consumed
            }
        }

        // DUP1-DUP16: byte 0x80-0x8f
        Instruction::UNKNOWN(b) if (0x80..=0x8f).contains(b) => {
            let n = (*b - 0x80 + 1) as usize;
            if n >= 1 && n <= stack.len() {
                let val = stack[stack.len() - n].clone();
                stack.push(val);
            }
        }

        // SWAP1-SWAP16: byte 0x90-0x9f
        Instruction::UNKNOWN(b) if (0x90..=0x9f).contains(b) => {
            let n = (*b - 0x90 + 1) as usize;
            if n + 1 <= stack.len() {
                let idx1 = stack.len() - 1;
                let idx2 = stack.len() - n - 1;
                stack.swap(idx1, idx2);
            }
        }

        // === MISC ===

        Instruction::PC => {
            stack.push(StackRegister {
                name: "pc".to_string(),
                exp: format!("{}", instr.pc),
                reg_type: StackRegisterType::Constant,
                value: Some(instr.pc as u64),
                offset: 0,
                last_modification_pc: instr.pc,
            });
        }

        Instruction::MSIZE => {
            stack.push(StackRegister {
                name: "msize".to_string(),
                exp: "msize".to_string(),
                reg_type: StackRegisterType::GasLimit, // environment-dependent
                value: None,
                offset: 0,
                last_modification_pc: instr.pc,
            });
        }

        Instruction::GAS => {
            stack.push(StackRegister {
                name: "gas".to_string(),
                exp: "gas".to_string(),
                reg_type: StackRegisterType::from_bits(
                    StackRegisterType::GasLimit as u32 | StackRegisterType::UserInputTainted as u32
                ),
                value: None,
                offset: 0,
                last_modification_pc: instr.pc,
            });
        }

        Instruction::JUMPDEST => {
            // No stack effect
        }

        // Default: no stack effect for unknown instructions
        _ => {}
    }
}

fn parse_push_value(bytes: &[u8]) -> u64 {
    let mut val: u64 = 0;
    for &b in bytes {
        val = (val << 8) | (b as u64);
    }
    val
}
