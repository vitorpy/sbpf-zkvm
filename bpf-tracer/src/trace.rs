//! Data structures for execution traces

use serde::{Deserialize, Serialize};

/// Complete execution trace of a BPF program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    /// Vector of instruction traces in execution order
    pub instructions: Vec<InstructionTrace>,
    /// Memory operations performed during execution
    pub memory_ops: Vec<MemoryOperation>,
    /// Initial register state at program start
    pub initial_registers: RegisterState,
    /// Final register state at program exit
    pub final_registers: RegisterState,
}

/// Trace of a single instruction execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionTrace {
    /// Program counter (instruction address)
    pub pc: u64,
    /// Raw instruction bytes
    pub instruction_bytes: Vec<u8>,
    /// Register state before instruction execution
    pub registers_before: RegisterState,
    /// Register state after instruction execution
    pub registers_after: RegisterState,
}

/// Memory operation (read or write)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOperation {
    /// Memory address
    pub address: u64,
    /// Value read or written
    pub value: u64,
    /// Operation type
    pub op_type: MemoryOpType,
}

/// Type of memory operation
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MemoryOpType {
    Read,
    Write,
}

/// State of all BPF registers (r0-r10) and PC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterState {
    /// General purpose registers r0-r10 and PC (r11)
    /// r0: return value
    /// r1-r5: function arguments
    /// r6-r9: callee saved
    /// r10: frame pointer (read-only)
    /// r11: program counter
    pub regs: [u64; 12],
}

impl RegisterState {
    /// Create new register state with all zeros
    pub fn new() -> Self {
        Self { regs: [0; 12] }
    }

    /// Create register state from array
    pub fn from_regs(regs: [u64; 12]) -> Self {
        Self { regs }
    }
}

impl Default for RegisterState {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionTrace {
    /// Create new empty execution trace
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            memory_ops: Vec::new(),
            initial_registers: RegisterState::new(),
            final_registers: RegisterState::new(),
        }
    }

    /// Get number of instructions executed
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Get number of memory operations
    pub fn memory_op_count(&self) -> usize {
        self.memory_ops.len()
    }
}

impl Default for ExecutionTrace {
    fn default() -> Self {
        Self::new()
    }
}
