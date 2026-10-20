pub mod disasm;
pub mod blocks;
pub mod taint;
pub mod analyzer;
pub mod semantics;
pub mod solkb;

pub use analyzer::analyze;
pub use analyzer::AnalysisResult;
pub use disasm::{decode_bytecode, DecodedInstruction, Instruction};
pub use blocks::{BasicBlock, build_basic_blocks, BlockFlags, NodeType};
pub use taint::{StackRegister, StackRegisterType, TaintAnalysis, BlockTaintResult};
pub use semantics::{SemanticAnalysis, SemanticFunction, SemanticFinding, run_semantic_analysis, detect_branching_vulnerabilities};
