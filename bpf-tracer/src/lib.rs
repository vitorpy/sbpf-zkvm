//! BPF Tracer - Execution trace capture for Solana BPF programs
//!
//! This crate wraps the solana-sbpf VM to instrument and record complete
//! execution traces including register state, memory operations, and instruction flow.
//!
//! # Overview
//!
//! The BPF tracer provides the ability to execute Solana BPF programs and capture
//! detailed traces of their execution, including:
//!
//! * Initial and final register states (r0-r10 + PC)
//! * Instruction-level traces with register states before/after each instruction
//! * Program counter (PC) and instruction bytes for each executed instruction
//!
//! # Usage
//!
//! ```no_run
//! use bpf_tracer::trace_program;
//!
//! // BPF bytecode: mov64 r0, 42; exit
//! let bytecode = &[
//!     0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00,  // mov64 r0, 42
//!     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // exit
//! ];
//!
//! let trace = trace_program(bytecode).unwrap();
//! println!("Executed {} instructions", trace.instruction_count());
//! println!("Final r0 value: {}", trace.final_registers.regs[0]);
//! ```
//!
//! # Limitations
//!
//! * Memory operation tracking is not yet implemented due to limitations in solana-sbpf's
//!   instrumentation API. The `memory_ops` field in `ExecutionTrace` will be empty.
//! * Programs must be valid BPF bytecode or ELF format supported by solana-sbpf.

pub mod trace;
pub mod vm;

pub use trace::{ExecutionTrace, InstructionTrace, MemoryOperation, MemoryOpType, RegisterState};
pub use vm::trace_program;

/// Result type for BPF tracer operations
pub type Result<T> = anyhow::Result<T>;
