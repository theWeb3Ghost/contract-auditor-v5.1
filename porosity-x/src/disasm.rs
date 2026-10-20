use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instruction {
    // 0x00
    STOP,
    ADD,
    MUL,
    SUB,
    DIV,
    SDIV,
    MOD,
    SMOD,
    ADDMOD,
    MULMOD,
    EXP,
    SIGNEXTEND,
    // 0x0d
    LT,
    GT,
    SLT,
    SGT,
    EQ,
    ISZERO,
    AND,
    OR,
    XOR,
    NOT,
    BYTE,
    SHL,
    SHR,
    SAR,
    // 0x1e-0x1f: reserved/unknown
    // 0x20: KECCAK256 (SHA3 in EVM terms)
    SHA3,
    // 0x20
    ADDRESS,
    BALANCE,
    ORIGIN,
    CALLER,
    CALLVALUE,
    CALLDATALOAD,
    CALLDATASIZE,
    CALLDATACOPY,
    CODESIZE,
    CODECOPY,
    GASPRICE,
    EXTCOORDSIZE,
    EXTCODESIZE,
    EXTCODECOPY,
    RETURNDATASIZE,
    RETURNDATACOPY,
    // 0x30
    BLOCKHASH,
    COINBASE,
    TIMESTAMP,
    NUMBER,
    DIFFICULTY,
    GASLIMIT,
    // 0x50
    POP,
    MLOAD,
    MSTORE,
    MSTORE8,
    SLOAD,
    SSTORE,
    JUMP,
    JUMPI,
    PC,
    MSIZE,
    GAS,
    // 0x5b
    JUMPDEST,
    // 0xa0-0xa4
    LOG0,
    LOG1,
    LOG2,
    LOG3,
    LOG4,
    // 0xf0-0xff
    CREATE,
    CALL,
    CALLCODE,
    RETURN,
    DELEGATECALL,
    CREATE2,
    // 0xfa
    STATICCALL,
    // 0xfd
    REVERT,
    // 0xff
    SELFDESTRUCT,
    // Special
    INVALID(u8),
    UNKNOWN(u8),
}

impl Instruction {
    /// EVM opcode table (matches go-ethereum/core/vm/opcodes.go)
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            // 0x00
            0x00 => Instruction::STOP,
            // 0x01-0x0b: arithmetic
            0x01 => Instruction::ADD,
            0x02 => Instruction::MUL,
            0x03 => Instruction::SUB,
            0x04 => Instruction::DIV,
            0x05 => Instruction::SDIV,
            0x06 => Instruction::MOD,
            0x07 => Instruction::SMOD,
            0x08 => Instruction::ADDMOD,
            0x09 => Instruction::MULMOD,
            0x0a => Instruction::EXP,
            0x0b => Instruction::SIGNEXTEND,
            // 0x10 range — comparison ops
            0x10 => Instruction::LT,
            0x11 => Instruction::GT,
            0x12 => Instruction::SLT,
            0x13 => Instruction::SGT,
            0x14 => Instruction::EQ,
            0x15 => Instruction::ISZERO,
            0x16 => Instruction::AND,
            0x17 => Instruction::OR,
            0x18 => Instruction::XOR,
            0x19 => Instruction::NOT,
            0x1a => Instruction::BYTE,
            0x1b => Instruction::SHL,
            0x1c => Instruction::SHR,
            0x1d => Instruction::SAR,
            0x1e => Instruction::UNKNOWN(0x1e), // CLC (reserved)
            0x1f => Instruction::UNKNOWN(0x1f),
            // 0x20: KECCAK256
            0x20 => Instruction::SHA3,
            // 0x30 range — closure state
            0x30 => Instruction::ADDRESS,
            0x31 => Instruction::BALANCE,
            0x32 => Instruction::ORIGIN,
            0x33 => Instruction::CALLER,
            0x34 => Instruction::CALLVALUE,
            0x35 => Instruction::CALLDATALOAD,
            0x36 => Instruction::CALLDATASIZE,
            0x37 => Instruction::CALLDATACOPY,
            0x38 => Instruction::CODESIZE,
            0x39 => Instruction::CODECOPY,
            0x3a => Instruction::GASPRICE,
            0x3b => Instruction::EXTCODESIZE,
            0x3c => Instruction::EXTCODECOPY,
            0x3d => Instruction::RETURNDATASIZE,
            0x3e => Instruction::RETURNDATACOPY,
            0x3f => Instruction::UNKNOWN(0x3f), // EXTCODEHASH (optional)
            // 0x40 range — block operations
            0x40 => Instruction::BLOCKHASH,
            0x41 => Instruction::COINBASE,
            0x42 => Instruction::TIMESTAMP,
            0x43 => Instruction::NUMBER,
            0x44 => Instruction::DIFFICULTY,
            0x45 => Instruction::GASLIMIT,
            0x46 => Instruction::UNKNOWN(0x46),
            0x47 => Instruction::UNKNOWN(0x47),
            0x48 => Instruction::UNKNOWN(0x48),
            0x49 => Instruction::UNKNOWN(0x49),
            0x4a => Instruction::UNKNOWN(0x4a),
            0x4b => Instruction::UNKNOWN(0x4b),
            0x4c => Instruction::UNKNOWN(0x4c),
            0x4d => Instruction::UNKNOWN(0x4d),
            0x4f => Instruction::UNKNOWN(0x4f),
            // 0x50 range — stack, memory, storage
            0x50 => Instruction::POP,
            0x51 => Instruction::MLOAD,
            0x52 => Instruction::MSTORE,
            0x53 => Instruction::MSTORE8,
            0x54 => Instruction::SLOAD,
            0x55 => Instruction::SSTORE,
            0x56 => Instruction::JUMP,
            0x57 => Instruction::JUMPI,
            0x58 => Instruction::PC,
            0x59 => Instruction::MSIZE,
            0x5a => Instruction::GAS,
            0x5b => Instruction::JUMPDEST,
            0x5c => Instruction::UNKNOWN(0x5c),
            0x5d => Instruction::UNKNOWN(0x5d),
            0x5e => Instruction::UNKNOWN(0x5e),
            0x5f => Instruction::UNKNOWN(0x5f),
            // PUSH1-PUSH32: 0x60-0x7f
            0x60..=0x7f => Instruction::UNKNOWN(byte),
            // DUP1-DUP16: 0x80-0x8f
            0x80..=0x8f => Instruction::UNKNOWN(byte),
            // SWAP1-SWAP16: 0x90-0x9f
            0x90..=0x9f => Instruction::UNKNOWN(byte),
            // LOG0-LOG4: 0xa0-0xa4
            0xa0 => Instruction::LOG0,
            0xa1 => Instruction::LOG1,
            0xa2 => Instruction::LOG2,
            0xa3 => Instruction::LOG3,
            0xa4 => Instruction::LOG4,
            // 0xa5-0xef: various opcodes
            0xa5 => Instruction::UNKNOWN(0xa5),
            0xa6 => Instruction::UNKNOWN(0xa6),
            0xa7 => Instruction::UNKNOWN(0xa7),
            0xa8 => Instruction::UNKNOWN(0xa8),
            0xa9 => Instruction::UNKNOWN(0xa9),
            0xaa => Instruction::UNKNOWN(0xaa),
            0xab => Instruction::UNKNOWN(0xab),
            0xac => Instruction::UNKNOWN(0xac),
            0xad => Instruction::UNKNOWN(0xad),
            0xae => Instruction::UNKNOWN(0xae),
            0xaf => Instruction::UNKNOWN(0xaf),
            0xb0 => Instruction::UNKNOWN(0xb0),
            0xb1 => Instruction::UNKNOWN(0xb1),
            0xb2 => Instruction::UNKNOWN(0xb2),
            0xb3 => Instruction::UNKNOWN(0xb3),
            0xb4 => Instruction::UNKNOWN(0xb4),
            0xb5 => Instruction::UNKNOWN(0xb5),
            0xb6 => Instruction::UNKNOWN(0xb6),
            0xb7 => Instruction::UNKNOWN(0xb7),
            0xb8 => Instruction::UNKNOWN(0xb8),
            0xb9 => Instruction::UNKNOWN(0xb9),
            0xba => Instruction::UNKNOWN(0xba),
            0xbb => Instruction::UNKNOWN(0xbb),
            0xbc => Instruction::UNKNOWN(0xbc),
            0xbd => Instruction::UNKNOWN(0xbd),
            0xbe => Instruction::UNKNOWN(0xbe),
            0xbf => Instruction::UNKNOWN(0xbf),
            // 0xc0-0xef: various
            0xc0 => Instruction::UNKNOWN(0xc0),
            0xc1 => Instruction::UNKNOWN(0xc1),
            0xc2 => Instruction::UNKNOWN(0xc2),
            0xc3 => Instruction::UNKNOWN(0xc3),
            0xc4 => Instruction::UNKNOWN(0xc4),
            0xc5 => Instruction::UNKNOWN(0xc5),
            0xc6 => Instruction::UNKNOWN(0xc6),
            0xc7 => Instruction::UNKNOWN(0xc7),
            0xc8 => Instruction::UNKNOWN(0xc8),
            0xc9 => Instruction::UNKNOWN(0xc9),
            0xca => Instruction::UNKNOWN(0xca),
            0xcb => Instruction::UNKNOWN(0xcb),
            0xcc => Instruction::UNKNOWN(0xcc),
            0xcd => Instruction::UNKNOWN(0xcd),
            0xce => Instruction::UNKNOWN(0xce),
            0xcf => Instruction::UNKNOWN(0xcf),
            0xd0 => Instruction::UNKNOWN(0xd0),
            0xd1 => Instruction::UNKNOWN(0xd1),
            0xd2 => Instruction::UNKNOWN(0xd2),
            0xd3 => Instruction::UNKNOWN(0xd3),
            0xd4 => Instruction::UNKNOWN(0xd4),
            0xd5 => Instruction::UNKNOWN(0xd5),
            0xd6 => Instruction::UNKNOWN(0xd6),
            0xd7 => Instruction::UNKNOWN(0xd7),
            0xd8 => Instruction::UNKNOWN(0xd8),
            0xd9 => Instruction::UNKNOWN(0xd9),
            0xda => Instruction::UNKNOWN(0xda),
            0xdb => Instruction::UNKNOWN(0xdb),
            0xdc => Instruction::UNKNOWN(0xdc),
            0xdd => Instruction::UNKNOWN(0xdd),
            0xde => Instruction::UNKNOWN(0xde),
            0xdf => Instruction::UNKNOWN(0xdf),
            0xe0 => Instruction::UNKNOWN(0xe0),
            0xe1 => Instruction::UNKNOWN(0xe1),
            0xe2 => Instruction::UNKNOWN(0xe2),
            0xe3 => Instruction::UNKNOWN(0xe3),
            0xe4 => Instruction::UNKNOWN(0xe4),
            0xe5 => Instruction::UNKNOWN(0xe5),
            0xe6 => Instruction::UNKNOWN(0xe6),
            0xe7 => Instruction::UNKNOWN(0xe7),
            0xe8 => Instruction::UNKNOWN(0xe8),
            0xe9 => Instruction::UNKNOWN(0xe9),
            0xea => Instruction::UNKNOWN(0xea),
            0xeb => Instruction::UNKNOWN(0xeb),
            0xec => Instruction::UNKNOWN(0xec),
            0xed => Instruction::UNKNOWN(0xed),
            0xee => Instruction::UNKNOWN(0xee),
            0xef => Instruction::UNKNOWN(0xef),
            // 0xf0-0xf3
            0xf0 => Instruction::CREATE,
            0xf1 => Instruction::CALL,
            0xf2 => Instruction::CALLCODE,
            0xf3 => Instruction::RETURN,
            // 0xf4
            0xf4 => Instruction::DELEGATECALL,
            // 0xf5-0xf9
            0xf5 => Instruction::UNKNOWN(0xf5),
            0xf6 => Instruction::UNKNOWN(0xf6),
            0xf7 => Instruction::UNKNOWN(0xf7),
            0xf8 => Instruction::UNKNOWN(0xf8),
            0xf9 => Instruction::UNKNOWN(0xf9),
            // 0xfa
            0xfa => Instruction::STATICCALL,
            // 0xfb-0xfc
            0xfb => Instruction::UNKNOWN(0xfb),
            0xfc => Instruction::UNKNOWN(0xfc),
            // 0xfd
            0xfd => Instruction::REVERT,
            // 0xfe
            0xfe => Instruction::INVALID(0xfe),
            // 0xff
            0xff => Instruction::SELFDESTRUCT,
            _ => Instruction::UNKNOWN(byte),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Instruction::STOP => "STOP",
            Instruction::ADD => "ADD",
            Instruction::MUL => "MUL",
            Instruction::SUB => "SUB",
            Instruction::DIV => "DIV",
            Instruction::SDIV => "SDIV",
            Instruction::MOD => "MOD",
            Instruction::SMOD => "SMOD",
            Instruction::ADDMOD => "ADDMOD",
            Instruction::MULMOD => "MULMOD",
            Instruction::EXP => "EXP",
            Instruction::SIGNEXTEND => "SIGNEXTEND",
            Instruction::LT => "LT",
            Instruction::GT => "GT",
            Instruction::SLT => "SLT",
            Instruction::SGT => "SGT",
            Instruction::EQ => "EQ",
            Instruction::ISZERO => "ISZERO",
            Instruction::AND => "AND",
            Instruction::OR => "OR",
            Instruction::XOR => "XOR",
            Instruction::NOT => "NOT",
            Instruction::BYTE => "BYTE",
            Instruction::SHL => "SHL",
            Instruction::SHR => "SHR",
            Instruction::SAR => "SAR",
            Instruction::SHA3 => "SHA3",
            Instruction::ADDRESS => "ADDRESS",
            Instruction::BALANCE => "BALANCE",
            Instruction::ORIGIN => "ORIGIN",
            Instruction::CALLER => "CALLER",
            Instruction::CALLVALUE => "CALLVALUE",
            Instruction::CALLDATALOAD => "CALLDATALOAD",
            Instruction::CALLDATASIZE => "CALLDATASIZE",
            Instruction::CALLDATACOPY => "CALLDATACOPY",
            Instruction::CODESIZE => "CODESIZE",
            Instruction::CODECOPY => "CODECOPY",
            Instruction::GASPRICE => "GASPRICE",
            Instruction::EXTCOORDSIZE => "EXTCOORDSIZE",
            Instruction::EXTCODESIZE => "EXTCODESIZE",
            Instruction::EXTCODECOPY => "EXTCODECOPY",
            Instruction::RETURNDATASIZE => "RETURNDATASIZE",
            Instruction::RETURNDATACOPY => "RETURNDATACOPY",
            Instruction::BLOCKHASH => "BLOCKHASH",
            Instruction::COINBASE => "COINBASE",
            Instruction::TIMESTAMP => "TIMESTAMP",
            Instruction::NUMBER => "NUMBER",
            Instruction::DIFFICULTY => "DIFFICULTY",
            Instruction::GASLIMIT => "GASLIMIT",
            Instruction::POP => "POP",
            Instruction::MLOAD => "MLOAD",
            Instruction::MSTORE => "MSTORE",
            Instruction::MSTORE8 => "MSTORE8",
            Instruction::SLOAD => "SLOAD",
            Instruction::SSTORE => "SSTORE",
            Instruction::JUMP => "JUMP",
            Instruction::JUMPI => "JUMPI",
            Instruction::PC => "PC",
            Instruction::MSIZE => "MSIZE",
            Instruction::GAS => "GAS",
            Instruction::JUMPDEST => "JUMPDEST",
            Instruction::LOG0 => "LOG0",
            Instruction::LOG1 => "LOG1",
            Instruction::LOG2 => "LOG2",
            Instruction::LOG3 => "LOG3",
            Instruction::LOG4 => "LOG4",
            Instruction::CREATE => "CREATE",
            Instruction::CALL => "CALL",
            Instruction::CALLCODE => "CALLCODE",
            Instruction::RETURN => "RETURN",
            Instruction::DELEGATECALL => "DELEGATECALL",
            Instruction::CREATE2 => "CREATE2",
            Instruction::STATICCALL => "STATICCALL",
            Instruction::REVERT => "REVERT",
            Instruction::SELFDESTRUCT => "SELFDESTRUCT",
            Instruction::UNKNOWN(_b) => "UNKNOWN",
            Instruction::INVALID(_b) => "INVALID",
        }
    }

    /// Returns (pops, pushes) — stack effect.
    /// Negative = net pop, positive = net push.
    /// For PUSH, pops=0, pushes=1 (but the data bytes are consumed in bytecode).
    pub fn stack_effect(&self) -> (i32, i32) {
        match self {
            // 0 stack
            Instruction::STOP | Instruction::JUMPDEST => (0, 0),
            Instruction::JUMP | Instruction::REVERT => (1, 0),
            // 1 pop, 0 push
            Instruction::POP | Instruction::RETURN | Instruction::SELFDESTRUCT => (1, 0),
            // 1 pop, 1 push
            Instruction::ADD | Instruction::MUL | Instruction::SUB | Instruction::DIV |
            Instruction::SDIV | Instruction::MOD | Instruction::SMOD | Instruction::ADDMOD |
            Instruction::MULMOD | Instruction::EXP | Instruction::SIGNEXTEND |
            Instruction::LT | Instruction::GT | Instruction::SLT | Instruction::SGT |
            Instruction::EQ | Instruction::AND | Instruction::OR | Instruction::XOR |
            Instruction::BYTE | Instruction::SHL | Instruction::SHR |
            Instruction::SAR | Instruction::SHA3 | Instruction::BALANCE |
            Instruction::CALLDATALOAD | Instruction::CODESIZE | Instruction::GASPRICE |
            Instruction::EXTCODESIZE | Instruction::BLOCKHASH |
            Instruction::COINBASE | Instruction::TIMESTAMP | Instruction::NUMBER |
            Instruction::DIFFICULTY | Instruction::GASLIMIT |
            Instruction::ISZERO | Instruction::NOT |
            Instruction::CALLER | Instruction::CALLVALUE | Instruction::ADDRESS |
            Instruction::ORIGIN | Instruction::CALLDATASIZE | Instruction::MSIZE |
            Instruction::PC | Instruction::GAS | Instruction::RETURNDATASIZE => (1, 1),
            // 2 pop, 0 push
            Instruction::JUMPI => (2, 0),
            // CREATE: 3 pop, 1 push
            Instruction::CREATE | Instruction::CREATE2 => (3, 1),
            // CALL: 7 pop, 1 push (on mainnet: returns success)
            Instruction::CALL | Instruction::CALLCODE => (7, 1),
            // DELEGATECALL/STATICCALL: 6 pop, 1 push
            Instruction::DELEGATECALL | Instruction::STATICCALL => (6, 1),
            // MLOAD: 1 pop, 1 push
            // MSTORE: 2 pop, 0 push
            Instruction::MSTORE | Instruction::MSTORE8 => (2, 0),
            // SLOAD: 1 pop, 1 push (but also reads from storage)
            // SSTORE: 2 pop, 0 push
            Instruction::SSTORE => (2, 0),
            // LOG0: 2 pop, 0 push (topics count varies)
            Instruction::LOG0 => (2, 0),
            Instruction::LOG1 => (3, 0),
            Instruction::LOG2 => (4, 0),
            Instruction::LOG3 => (5, 0),
            Instruction::LOG4 => (6, 0),
            // CALLDATALOAD: 1 pop, 1 push
            // CODECOPY: 3 pop, 0 push
            Instruction::CODECOPY | Instruction::CALLDATACOPY | Instruction::RETURNDATACOPY => (3, 0),
            // EXTCODECOPY: 4 pop, 0 push
            Instruction::EXTCODECOPY => (4, 0),
            // RETURNDATACOPY: 3 pop, 0 push
            // INVALID: 0 stack
            Instruction::INVALID(_) => (0, 0),
            // Default for unknown: 0, 0
            _ => {
                // Check if it's a PUSH instruction (UNKNOWN with byte 0x60-0x7f)
                if let Instruction::UNKNOWN(b) = self {
                    if (0x60..=0x7f).contains(b) {
                        return (0, 1); // PUSH pushes a value
                    }
                    if (0x80..=0x8f).contains(b) {
                        return (0, 0); // DUP doesn't change net stack
                    }
                    if (0x90..=0x9f).contains(b) {
                        return (0, 0); // SWAP doesn't change net stack
                    }
                }
                (0, 0)
            }
        }
    }

    /// Returns the number of immediate bytes (for PUSH instructions)
    pub fn immediate_bytes(&self) -> usize {
        match self {
            Instruction::UNKNOWN(b) if (0x60..=0x7f).contains(b) => (*b as u8 - 0x60 + 1) as usize,
            _ => 0,
        }
    }

    /// Whether this instruction causes a control flow divergence
    pub fn is_terminator(&self) -> bool {
        matches!(
            self,
            Instruction::STOP |
            Instruction::JUMP |
            Instruction::JUMPI |
            Instruction::RETURN |
            Instruction::REVERT |
            Instruction::SELFDESTRUCT |
            Instruction::INVALID(_)
        )
    }

    /// Whether this is a function entry point
    pub fn is_jumpdest(&self) -> bool {
        matches!(self, Instruction::JUMPDEST)
    }

    /// Whether this is a CALL variant
    pub fn is_call(&self) -> bool {
        matches!(
            self,
            Instruction::CALL |
            Instruction::CALLCODE |
            Instruction::DELEGATECALL |
            Instruction::STATICCALL
        )
    }

    /// The call type if this is a CALL-family instruction
    pub fn call_type(&self) -> Option<&'static str> {
        match self {
            Instruction::CALL => Some("CALL"),
            Instruction::CALLCODE => Some("CALLCODE"),
            Instruction::DELEGATECALL => Some("DELEGATECALL"),
            Instruction::STATICCALL => Some("STATICCALL"),
            _ => None,
        }
    }

    /// Number of stack args this CALL consumes (before the gas offset)
    pub fn call_arg_count(&self) -> usize {
        match self {
            // CALL: 7 args (gas, addr, value, argsOffset, argsSize, retOffset, retSize)
            Instruction::CALL | Instruction::CALLCODE => 7,
            // STATICCALL/DELEGATECALL: 6 args (no value)
            Instruction::DELEGATECALL | Instruction::STATICCALL => 6,
            _ => 0,
        }
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A decoded instruction with its position in bytecode
#[derive(Debug, Clone)]
pub struct DecodedInstruction {
    pub pc: u32,
    pub opcode: Instruction,
    pub immediate: Vec<u8>,  // for PUSH instructions
    pub immediate_hex: String,
}

impl DecodedInstruction {
    pub fn stack_effect(&self) -> (i32, i32) {
        self.opcode.stack_effect()
    }

    pub fn operand_string(&self) -> String {
        if self.immediate.is_empty() {
            String::new()
        } else {
            self.immediate_hex.clone()
        }
    }
}

/// Decode a full bytecode stream into instructions
pub fn decode_bytecode(bytecode: &[u8]) -> Vec<DecodedInstruction> {
    let mut instructions = Vec::new();
    let mut pc: usize = 0;

    while pc < bytecode.len() {
        let byte = bytecode[pc];
        let opcode = Instruction::from_byte(byte);
        let imm_len = opcode.immediate_bytes();

        let mut immediate = Vec::new();
        let mut immediate_hex = String::new();

        if pc + 1 + imm_len <= bytecode.len() && imm_len > 0 {
            immediate = bytecode[pc + 1..pc + 1 + imm_len].to_vec();
            immediate_hex = format!("0x{}", hex::encode(&immediate));
        }

        instructions.push(DecodedInstruction {
            pc: pc as u32,
            opcode,
            immediate,
            immediate_hex,
        });

        pc += 1 + imm_len;

        // If this is a terminator, stop decoding this path
        // (but we continue to capture all instructions for analysis)
    }

    instructions
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
