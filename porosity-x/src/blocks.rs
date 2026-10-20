use crate::disasm::{DecodedInstruction, Instruction};
use std::collections::HashMap;

/// Block flags ported from Porosity's BlockFlags enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockFlags {
    pub no_more_sstore: bool,  // Set when CALL encountered (reentrancy detection)
}

/// A basic block in the CFG
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: u32,
    pub offset: u32,
    pub size: u32,
    pub instructions: Vec<DecodedInstruction>,
    pub next_default: Option<u32>,   // Fallthrough successor
    pub next_jumpi: Option<u32>,    // Conditional jump successor
    pub dst_default: Option<u32>,   // Default jump target (from JUMP)
    pub dst_jumpi: Option<u32>,     // Conditional jump target (from JUMPI)
    pub references: Vec<(u32, NodeType)>,  // (offset, conditionality)
    pub visited: bool,
    pub walked: bool,
    pub flags: BlockFlags,
    pub inherit_flags: BlockFlags,
    pub dominators: Vec<u32>,  // Simplified: set of block IDs that dominate this block
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    RegularNode,
    ConditionalNode,
    ExitNode,
}

impl Default for NodeType {
    fn default() -> Self {
        NodeType::RegularNode
    }
}

/// Build basic blocks from decoded instructions
/// Port of Porosity's enumerateInstructionsAndBlocks() + assignXrefToBlocks()
pub fn build_basic_blocks(instructions: &[DecodedInstruction], bytecode: &[u8]) -> Vec<BasicBlock> {
    // Find all JUMPDEST offsets (block boundaries)
    let mut jumpdest_offsets: Vec<u32> = Vec::new();
    for instr in instructions {
        if instr.opcode.is_jumpdest() {
            jumpdest_offsets.push(instr.pc);
        }
    }

    // Find all JUMP/JUMPI targets
    let mut jump_targets: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for instr in instructions {
        match &instr.opcode {
            Instruction::JUMP => {
                // Target is on the stack — for constant PUSH before JUMP pattern,
                // we can extract it. For now, we'll resolve at taint time.
            }
            Instruction::JUMPI => {
                // Same as JUMP
            }
            _ => {
                // For PUSH instructions that look like jump targets,
                // check if the pushed value is a valid JUMPDEST
                if let Instruction::UNKNOWN(b) = instr.opcode {
                    if (0x60..=0x7f).contains(&b) && !instr.immediate.is_empty() {
                        if let Ok(target) = parse_push_value(&instr.immediate) {
                            if jumpdest_offsets.contains(&(target as u32)) {
                                jump_targets.insert(target as u32);
                            }
                        }
                    }
                }
            }
        }
    }

    // Add 0 as the first block always starts at offset 0
    let mut block_starts: Vec<u32> = vec![0];
    block_starts.extend(jumpdest_offsets.clone());
    block_starts.extend(jump_targets);

    // Add fallthrough targets of JUMPI as block starts
    // JUMPI's fallthrough is the next instruction after the full instruction
    for instr in instructions {
        if instr.opcode.is_jumpdest() {
            continue; // already handled
        }
        if matches!(instr.opcode, Instruction::JUMPI) {
            let fallthrough = instr.pc + 1; // JUMPI has no immediate bytes
            block_starts.push(fallthrough);
        }
    }

    block_starts.sort();
    block_starts.dedup();

    // Map from PC to instruction index
    let mut pc_to_idx: HashMap<u32, usize> = HashMap::new();
    for (idx, instr) in instructions.iter().enumerate() {
        pc_to_idx.insert(instr.pc, idx);
    }

    // Build blocks
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut block_id: u32 = 0;
    let mut block_id_map: HashMap<u32, u32> = HashMap::new(); // offset -> id

    for (i, &start_offset) in block_starts.iter().enumerate() {
        let end_offset = if i + 1 < block_starts.len() {
            block_starts[i + 1]
        } else {
            // Last block extends to end of bytecode
            bytecode.len() as u32
        };

        // Collect instructions in this block
        let mut block_instructions: Vec<DecodedInstruction> = Vec::new();
        let mut pc = start_offset;
        while pc < end_offset {
            if let Some(&idx) = pc_to_idx.get(&pc) {
                let instr = &instructions[idx];
                block_instructions.push(instr.clone());

                // If terminator, block ends here
                if instr.opcode.is_terminator() {
                    pc = end_offset; // force end
                } else {
                    pc = instr.pc + 1 + instr.opcode.immediate_bytes() as u32;
                }
            } else {
                break;
            }
        }

        if block_instructions.is_empty() {
            continue;
        }

        block_id_map.insert(start_offset, block_id);
        blocks.push(BasicBlock {
            id: block_id,
            offset: start_offset,
            size: block_instructions.len() as u32,
            instructions: block_instructions,
            next_default: None,
            next_jumpi: None,
            dst_default: None,
            dst_jumpi: None,
            references: Vec::new(),
            visited: false,
            walked: false,
            flags: BlockFlags::default(),
            inherit_flags: BlockFlags::default(),
            dominators: Vec::new(),
        });
        block_id += 1;
    }

    // Collect all JUMPDEST offsets for cross-block resolution
    let jumpdest_offsets: std::collections::HashSet<u32> = blocks
        .iter()
        .filter(|b| !b.instructions.is_empty() && b.instructions[0].opcode.is_jumpdest())
        .map(|b| b.offset)
        .collect();

    // Now compute edges and cross-references
    // We need two passes: first pass with just current-block resolution,
    // second pass uses cross-block context for unresolved jumps
    for pass in 0..2u32 {
        for block_idx in 0..blocks.len() {
            let last_instr = blocks[block_idx].instructions.last();
            if let Some(instr) = last_instr {
                match &instr.opcode {
                    Instruction::JUMP => {
                        let target = if pass == 0 {
                            // Pass 0: try simple PUSH+JUMP backward search first
                            resolve_jump_target(&blocks[block_idx].instructions)
                        } else {
                            // Pass 1: try stack-aware tracking for computed jumps
                            track_stack_for_jump_target(&blocks[block_idx].instructions)
                                .or_else(|| resolve_jump_target(&blocks[block_idx].instructions))
                                .or_else(|| resolve_jump_target_cross_block(&blocks, blocks[block_idx].id, &jumpdest_offsets))
                        };
                        if let Some(t) = target {
                            blocks[block_idx].dst_default = Some(t);
                            if let Some(&id) = block_id_map.get(&t) {
                                blocks[block_idx].next_default = Some(id);
                            } else if pass == 1 && t > bytecode.len() as u32 {
                                // Jump target is beyond bytecode — truncated bytecode.
                                // Mark as an external/return-to-caller jump so semantic
                                // analysis can still treat the current block as having
                                // an exit (e.g., function return to caller).
                                blocks[block_idx].dst_default = Some(t);
                            }
                        } else if pass == 1 {
                            // Final fallback: try the nearest JUMPDEST after this block's
                            // last instruction as a potential target. This handles
                            // computed jumps (e.g., return addresses from CALL).
                            let last_pc = blocks[block_idx].instructions.last().map(|i| i.pc + 1).unwrap_or(0);
                            for &jd in jumpdest_offsets.iter() {
                                if jd >= last_pc {
                                    if let Some(&id) = block_id_map.get(&jd) {
                                        blocks[block_idx].dst_default = Some(jd);
                                        blocks[block_idx].next_default = Some(id);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Instruction::JUMPI => {
                        // Try stack-aware tracking, then backward PUSH search, then cross-block
                        let target = if pass == 0 {
                            track_stack_for_jumpi_target(&blocks[block_idx].instructions)
                                .or_else(|| resolve_jumpi_targets(&blocks[block_idx].instructions).0)
                        } else {
                            track_stack_for_jumpi_target(&blocks[block_idx].instructions)
                                .or_else(|| resolve_jump_target(&blocks[block_idx].instructions))
                                .or_else(|| resolve_jump_target_cross_block(&blocks, blocks[block_idx].id, &jumpdest_offsets))
                        };
                        if let Some(t) = target {
                            blocks[block_idx].dst_jumpi = Some(t);
                            if let Some(&id) = block_id_map.get(&t) {
                                blocks[block_idx].next_jumpi = Some(id);
                            } else if pass == 1 && t > bytecode.len() as u32 {
                                // Jump target beyond bytecode — truncated bytecode
                                blocks[block_idx].dst_jumpi = Some(t);
                            }
                        }
                        // Fallthrough: next block in sequence (after last instruction)
                        let next_offset = blocks[block_idx].instructions.last().map(|i| i.pc + 1).unwrap_or(0);
                        blocks[block_idx].dst_default = Some(next_offset);
                        if let Some(&id) = block_id_map.get(&next_offset) {
                            blocks[block_idx].next_default = Some(id);
                        }
                    }
                    Instruction::STOP
                    | Instruction::RETURN
                    | Instruction::REVERT
                    | Instruction::SELFDESTRUCT => {
                        // Exit nodes — no successors
                    }
                    _ => {
                        // Fallthrough to next block
                        let next_offset = blocks[block_idx].instructions.last().map(|i| i.pc + 1).unwrap_or(0);
                        if block_starts.contains(&next_offset) {
                            blocks[block_idx].dst_default = Some(next_offset);
                            if let Some(&id) = block_id_map.get(&next_offset) {
                                blocks[block_idx].next_default = Some(id);
                            }
                        }
                    }
                }
            }
        }
    }

    // Build references (who points to whom)
    // First collect all references, then apply — avoids double mutable borrow
    let mut collected_refs: Vec<(u32, u32, NodeType)> = Vec::new();
    for block in &blocks {
        if let Some(target) = block.next_default {
            let node_type = if block.dst_jumpi.is_some() {
                NodeType::ConditionalNode
            } else {
                NodeType::RegularNode
            };
            collected_refs.push((target, block.id, node_type));
        }
        if let Some(target) = block.next_jumpi {
            collected_refs.push((target, block.id, NodeType::ConditionalNode));
        }
    }

    for (target_id, src_id, node_type) in &collected_refs {
        if let Some(target_block) = blocks.iter_mut().find(|b| b.id == *target_id) {
            target_block.references.push((*src_id, *node_type));
        }
    }

    // Compute dominators
    compute_dominators(&mut blocks);

    blocks
}

/// Parse a PUSH immediate value as a u64 target
fn parse_push_value(bytes: &[u8]) -> Result<u64, ()> {
    if bytes.len() > 8 {
        return Err(());
    }
    let mut val: u64 = 0;
    for &b in bytes {
        val = (val << 8) | (b as u64);
    }
    Ok(val)
}

/// Represent a value that could be on the stack during symbolic stack tracking.
/// Concrete values come from PUSH instructions; computed values come from
/// arithmetic operations (ADD, SUB, MUL, etc.) where both operands are known.
#[derive(Debug, Clone)]
enum StackVal {
    Concrete(u64),
    Computed(u64),  // Result of an arithmetic operation, still a known value
    Unknown,        // Result of external state, CALL, or complex computation
}

impl StackVal {
    fn as_u32(&self) -> Option<u32> {
        match self {
            StackVal::Concrete(v) | StackVal::Computed(v) => {
                if *v < u32::MAX as u64 { Some(*v as u32) } else { None }
            }
            StackVal::Unknown => None,
        }
    }
}

/// Resolve jump target by looking for PUSH+JUMP pattern.
/// Searches the entire block backwards for a PUSH that could be the jump target.
/// In EVM, JUMP pops the top of stack as the destination. The PUSH that set it
/// may not be the immediately preceding instruction — it could be buried under
/// multiple POP/ADD/other operations if there was stack manipulation between them.
///
/// We search backwards through the entire block. The first PUSH we find is the
/// most likely candidate for the jump target.
fn resolve_jump_target(instructions: &[DecodedInstruction]) -> Option<u32> {
    for instr in instructions.iter().rev() {
        if let Instruction::UNKNOWN(b) = instr.opcode {
            if (0x60..=0x7f).contains(&b) && !instr.immediate.is_empty() {
                if let Ok(val) = parse_push_value(&instr.immediate) {
                    if val < u32::MAX as u64 {
                        return Some(val as u32);
                    }
                }
            }
        }
    }
    None
}

/// Track stack values through a block to find the actual jump target.
/// This handles computed jumps like `PUSH2(target) ADD JUMP` where the
/// target is computed through arithmetic operations.
///
/// We simulate a limited stack (up to 1024 slots) walking forward through
/// the block. PUSH pushes concrete values, arithmetic ops combine top elements,
/// POP removes top, DUP duplicates, SWAP swaps.
fn track_stack_for_jump_target(instructions: &[DecodedInstruction]) -> Option<u32> {
    let mut stack: Vec<StackVal> = Vec::with_capacity(32);

    for instr in instructions {
        // Handle stack manipulation that depends on opcode type
        let (pops, pushes) = instr.opcode.stack_effect();

        // Handle special-case instructions that compute values
        match &instr.opcode {
            // PUSH pushes concrete value
            Instruction::UNKNOWN(b) if (0x60..=0x7f).contains(b) => {
                if let Ok(val) = parse_push_value(&instr.immediate) {
                    stack.push(StackVal::Concrete(val));
                } else {
                    stack.push(StackVal::Unknown);
                }
                continue;
            }
            // DUPn: duplicate nth item from top
            Instruction::UNKNOWN(b) if (0x80..=0x8f).contains(b) => {
                let n = (*b - 0x80) + 1;
                if stack.len() >= n as usize {
                    let idx = stack.len() - n as usize;
                    let val = stack[idx].clone();
                    stack.push(val);
                } else {
                    stack.push(StackVal::Unknown);
                }
                continue;
            }
            // SWAPn: swap top with nth item
            Instruction::UNKNOWN(b) if (0x90..=0x9f).contains(b) => {
                let n = (*b - 0x90) + 1;
                if stack.len() >= n as usize {
                    let idx = stack.len() - n as usize;
                    let last_idx = stack.len() - 1;
                    stack.swap(idx, last_idx);
                }
                continue;
            }
            // Arithmetic: combine top two stack elements
            Instruction::ADD | Instruction::SUB | Instruction::MUL | Instruction::DIV | Instruction::SDIV
            | Instruction::MOD | Instruction::SMOD | Instruction::ADDMOD | Instruction::MULMOD
            | Instruction::EXP | Instruction::SHL | Instruction::SHR | Instruction::SAR => {
                if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                    let result = match (a, b) {
                        (StackVal::Concrete(va), StackVal::Concrete(vb)) => {
                            let r = match instr.opcode {
                                Instruction::ADD => va.wrapping_add(vb),
                                Instruction::SUB => va.wrapping_sub(vb),
                                Instruction::MUL => va.wrapping_mul(vb),
                                Instruction::DIV => if vb == 0 { 0 } else { va / vb },
                                Instruction::SDIV => {
                                    if vb == 0 { 0 } else {
                                        ((va as i64 as i128) / (vb as i64 as i128)) as u64
                                    }
                                }
                                Instruction::MOD => if vb == 0 { 0 } else { va % vb },
                                Instruction::SMOD => {
                                    if vb == 0 { 0 } else {
                                        ((va as i64) % (vb as i64)) as u64
                                    }
                                }
                                Instruction::ADDMOD => va.wrapping_add(vb),
                                Instruction::MULMOD => va.wrapping_mul(vb),
                                Instruction::EXP => va.pow(vb as u32),
                                Instruction::SHL => va << (vb % 256),
                                Instruction::SHR => va >> (vb % 256),
                                Instruction::SAR => {
                                    if va >= (1u64 << 63) {
                                        ((va as i64) >> (vb % 64)) as u64
                                    } else {
                                        va >> (vb % 64)
                                    }
                                }
                                _ => va,
                            };
                            StackVal::Computed(r)
                        }
                        _ => StackVal::Unknown,
                    };
                    stack.push(result);
                }
                continue;
            }
            // Bitwise: AND, OR, XOR combine two; NOT negates one
            Instruction::AND | Instruction::OR | Instruction::XOR => {
                if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                    let result = match (a, b) {
                        (StackVal::Concrete(va), StackVal::Concrete(vb)) => {
                            let r = match instr.opcode {
                                Instruction::AND => va & vb,
                                Instruction::OR => va | vb,
                                Instruction::XOR => va ^ vb,
                                _ => va,
                            };
                            StackVal::Computed(r)
                        }
                        _ => StackVal::Unknown,
                    };
                    stack.push(result);
                }
                continue;
            }
            Instruction::NOT => {
                if let Some(v) = stack.pop() {
                    let result = match v {
                        StackVal::Concrete(val) => StackVal::Computed(!val),
                        _ => StackVal::Unknown,
                    };
                    stack.push(result);
                }
                continue;
            }
            // Comparison operations produce 0 or 1
            Instruction::LT | Instruction::GT | Instruction::SLT | Instruction::SGT | Instruction::EQ => {
                stack.pop(); // cond b
                stack.pop(); // cond a
                stack.push(StackVal::Concrete(1));
                continue;
            }
            // ISZERO negates
            Instruction::ISZERO => {
                if let Some(v) = stack.pop() {
                    let result = match v {
                        StackVal::Concrete(val) => StackVal::Concrete(if val == 0 { 1 } else { 0 }),
                        StackVal::Computed(val) => StackVal::Computed(if val == 0 { 1 } else { 0 }),
                        _ => StackVal::Unknown,
                    };
                    stack.push(result);
                }
                continue;
            }
            // POP
            Instruction::POP => {
                stack.pop();
                continue;
            }
            // Instructions that push a single value (but not PUSH/DUP/SWAP which are handled above)
            Instruction::CALLVALUE | Instruction::CALLDATALOAD | Instruction::CALLDATASIZE
            | Instruction::MSIZE | Instruction::PC | Instruction::GAS | Instruction::MLOAD
            | Instruction::SLOAD | Instruction::ADDRESS | Instruction::ORIGIN | Instruction::CALLER
            | Instruction::GASPRICE | Instruction::COINBASE | Instruction::NUMBER | Instruction::TIMESTAMP
            | Instruction::DIFFICULTY | Instruction::GASLIMIT | Instruction::BLOCKHASH
            | Instruction::BALANCE | Instruction::EXTCODESIZE | Instruction::EXTCOORDSIZE => {
                stack.push(StackVal::Unknown);
                continue;
            }
            // External calls push a result
            Instruction::CALL | Instruction::CALLCODE | Instruction::DELEGATECALL
            | Instruction::STATICCALL | Instruction::CREATE | Instruction::CREATE2
            | Instruction::SHA3 => {
                // Pop call args first (already handled by stack_effect), then push result
                stack.push(StackVal::Unknown);
                continue;
            }
            // Multi-pop instructions that don't push anything
            Instruction::MSTORE | Instruction::MSTORE8 | Instruction::SSTORE
            | Instruction::LOG0 | Instruction::LOG1 | Instruction::LOG2 | Instruction::LOG3 | Instruction::LOG4
            | Instruction::CODECOPY | Instruction::CALLDATACOPY | Instruction::RETURNDATACOPY
            | Instruction::EXTCODECOPY | Instruction::RETURN | Instruction::REVERT
            | Instruction::STOP | Instruction::SELFDESTRUCT => {
                // These are handled by stack_effect - pop happens below
                continue;
            }
            // JUMP: pops one (destination), returns it immediately
            Instruction::JUMP => {
                let target = stack.pop()?;
                return target.as_u32();
            }
            // JUMPI: pops two (destination, condition) — destination is top
            Instruction::JUMPI => {
                let target = stack.pop()?;
                let _condition = stack.pop();
                return target.as_u32();
            }
            _ => {}
        }

        // Generic: pop consumed values, then handle push for unhandled opcodes
        for _ in 0..pops {
            stack.pop();
        }
        // For instructions that push but weren't handled above, push Unknown
        // (PUSH, DUP, SWAP are already handled via continue above)
        if pushes > 0 {
            let already_handled = matches!(instr.opcode,
                Instruction::UNKNOWN(b) if (0x60..=0x7f).contains(&b)
                    || (0x80..=0x8f).contains(&b)
                    || (0x90..=0x9f).contains(&b));
            if !already_handled {
                // Check if it was handled by a special case above
                let special_handled = matches!(instr.opcode,
                    Instruction::CALLVALUE | Instruction::CALLDATALOAD | Instruction::CALLDATASIZE
                    | Instruction::MSIZE | Instruction::PC | Instruction::GAS | Instruction::MLOAD
                    | Instruction::SLOAD | Instruction::ADDRESS | Instruction::ORIGIN | Instruction::CALLER
                    | Instruction::GASPRICE | Instruction::COINBASE | Instruction::NUMBER | Instruction::TIMESTAMP
                    | Instruction::DIFFICULTY | Instruction::GASLIMIT | Instruction::BLOCKHASH
                    | Instruction::BALANCE | Instruction::EXTCODESIZE | Instruction::EXTCOORDSIZE
                    | Instruction::CALL | Instruction::CALLCODE | Instruction::DELEGATECALL
                    | Instruction::STATICCALL | Instruction::CREATE | Instruction::CREATE2
                    | Instruction::SHA3);
                if !special_handled {
                    stack.push(StackVal::Unknown);
                }
            }
        }
    }

    // After processing all instructions, check if the top of stack is a concrete value
    // that's a valid JUMPDEST
    stack.last()?.as_u32()
}

/// Track stack values through a block to find the JUMPI target and condition.
/// For JUMPI: pops (destination, condition) — destination is top, condition is below.
/// Returns the jump target (the value that was on top of stack when JUMPI executed).
fn track_stack_for_jumpi_target(instructions: &[DecodedInstruction]) -> Option<u32> {
    track_stack_for_jump_target(instructions)
}

/// Resolve both jump target and fallthrough for JUMPI.
/// Searches the entire block backwards for PUSH instructions.
/// For JUMPI, the EVM pops two stack items:
///   pos = first pop = the jump DESTINATION (top of stack)
///   cond = second pop = the CONDITION
/// The first PUSH found when walking backwards is the most likely jump target.
fn resolve_jumpi_targets(instructions: &[DecodedInstruction]) -> (Option<u32>, Option<u32>) {
    let mut target: Option<u32> = None;

    // Walk backwards through the ENTIRE block to find the nearest PUSH
    for instr in instructions.iter().rev() {
        if let Instruction::UNKNOWN(b) = instr.opcode {
            if (0x60..=0x7f).contains(&b) {
                if let Ok(val) = parse_push_value(&instr.immediate) {
                    target = Some(val as u32);
                    break;
                }
            }
        }
    }

    // Fallthrough is the next instruction after JUMPI
    let fallthrough = match instructions.last() {
        Some(instr) => instr.pc + 1,
        None => 0,
    };

    (target, Some(fallthrough))
}

/// Cross-block jump target resolution for JUMP.
/// When the current block has no resolvable PUSH, search ALL instructions
/// before this block for the nearest PUSH-to-JUMPDEST.
/// This handles patterns where the jump target was pushed earlier in the
/// function and is computed through arithmetic or buried under stack operations.
fn resolve_jump_target_cross_block(
    blocks: &[BasicBlock],
    current_block_id: u32,
    jumpdest_offsets: &std::collections::HashSet<u32>,
) -> Option<u32> {
    let current_block = blocks.iter().find(|b| b.id == current_block_id)?;

    // First try within current block
    if let Some(t) = resolve_jump_target(&current_block.instructions) {
        return Some(t);
    }

    // Broader search: look at ALL instructions before this block for PUSH-to-JUMPDESTs.
    // The nearest (closest PC-wise) PUSH-to-JUMPDEST before this block is the
    // most likely jump target.
    let current_pc = current_block.instructions.first().map(|i| i.pc)?;
    let current_offset = current_block.offset;
    let mut found_target: Option<u32> = None;
    let mut found_pc: u32 = 0;

    for block in blocks {
        for instr in &block.instructions {
            if instr.pc >= current_pc {
                continue;
            }
            if let Instruction::UNKNOWN(b) = instr.opcode {
                if (0x60..=0x7f).contains(&b) && !instr.immediate.is_empty() {
                    if let Ok(val) = parse_push_value(&instr.immediate) {
                        if val < u32::MAX as u64 {
                            let target_u32 = val as u32;
                            // Exclude self-jumps (target is the current block)
                            if jumpdest_offsets.contains(&target_u32) && target_u32 != current_offset {
                                if instr.pc >= found_pc {
                                    found_target = Some(target_u32);
                                    found_pc = instr.pc;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    found_target
}

/// Cross-block jump target resolution for JUMPI.
/// Similar to resolve_jump_target_cross_block but for JUMPI (returns target and fallthrough).
fn resolve_jumpi_targets_cross_block(
    blocks: &[BasicBlock],
    current_block_id: u32,
    jumpdest_offsets: &std::collections::HashSet<u32>,
) -> (Option<u32>, Option<u32>) {
    let current_block = blocks.iter().find(|b| b.id == current_block_id);

    if let Some(block) = current_block {
        // First try within-block resolution
        let (target, fallthrough) = resolve_jumpi_targets(&block.instructions);
        if target.is_some() {
            return (target, fallthrough);
        }

        // Broader search: look for PUSH-to-JUMPDEST before this block
        let current_pc = block.instructions.first().map(|i| i.pc);
        let mut found_target: Option<u32> = None;
        let mut found_pc: u32 = 0;

        if let Some(cur_pc) = current_pc {
            for blk in blocks {
                for instr in &blk.instructions {
                    if instr.pc >= cur_pc {
                        continue;
                    }
                    if let Instruction::UNKNOWN(b) = instr.opcode {
                        if (0x60..=0x7f).contains(&b) && !instr.immediate.is_empty() {
                            if let Ok(val) = parse_push_value(&instr.immediate) {
                                if val < u32::MAX as u64 {
                                    let target_u32 = val as u32;
                                    if jumpdest_offsets.contains(&target_u32) {
                                        if instr.pc >= found_pc {
                                            found_target = Some(target_u32);
                                            found_pc = instr.pc;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some(t) = found_target {
            let fallthrough = block.instructions.last().map(|i| i.pc + 1);
            return (Some(t), fallthrough);
        }
    }

    (None, None)
}

/// Compute dominator sets for all blocks
/// Dominator(n) = {n} ∪ ∩(Dominator(p) for all predecessors p)
fn compute_dominators(blocks: &mut [BasicBlock]) {
    let entry_id = blocks.first().map(|b| b.id).unwrap_or(0);

    // Build predecessor map
    let mut predecessors: HashMap<u32, Vec<u32>> = HashMap::new();
    for block in blocks.iter() {
        if let Some(target) = block.next_default {
            predecessors.entry(target).or_default().push(block.id);
        }
        if let Some(target) = block.next_jumpi {
            predecessors.entry(target).or_default().push(block.id);
        }
    }

    // Initialize: every block is dominated by itself, plus all blocks for entry
    for block in blocks.iter_mut() {
        block.dominators = vec![block.id];
    }

    let _entry = blocks.iter_mut().find(|b| b.id == entry_id);

    // Iterate until fixpoint
    let mut changed = true;
    let max_iter = 100;
    let mut iter = 0;

    while changed && iter < max_iter {
        changed = false;
        iter += 1;

        // Pre-compute dominator sets to avoid borrow issues
        let mut updates: Vec<(u32, Vec<u32>)> = Vec::new();

        for block in &*blocks {
            if block.id == entry_id {
                continue;
            }

            let preds = predecessors.get(&block.id).cloned().unwrap_or_default();

            if preds.is_empty() {
                updates.push((block.id, vec![block.id]));
                continue;
            }

            // Get dominator sets of all predecessors
            let pred_dom_sets: Vec<std::collections::HashSet<u32>> = preds
                .iter()
                .filter_map(|&pred_id| {
                    blocks.iter().find(|b| b.id == pred_id).map(|b| b.dominators.iter().cloned().collect())
                })
                .collect();

            if pred_dom_sets.is_empty() {
                continue;
            }

            // Intersection of all predecessor dominator sets
            let mut intersection: std::collections::HashSet<u32> =
                pred_dom_sets[0].iter().cloned().collect();
            for dom_set in &pred_dom_sets[1..] {
                intersection = intersection.intersection(dom_set).cloned().collect();
            }

            // Add self
            intersection.insert(block.id);

            let mut new_doms: Vec<u32> = intersection.into_iter().collect();
            new_doms.sort();

            if new_doms != block.dominators {
                updates.push((block.id, new_doms));
            }
        }

        // Apply updates
        for (id, new_doms) in updates {
            if let Some(block) = blocks.iter_mut().find(|b| b.id == id) {
                block.dominators = new_doms;
                changed = true;
            }
        }
    }
}
