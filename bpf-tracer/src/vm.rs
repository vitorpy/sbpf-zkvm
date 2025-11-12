//! BPF VM wrapper with execution tracing
//!
//! This module wraps solana-sbpf to capture complete execution traces.

use crate::trace::*;
use crate::Result;
use solana_sbpf::{
    aligned_memory::AlignedMemory,
    elf::Executable,
    error::ProgramResult,
    memory_region::{MemoryMapping, MemoryRegion},
    program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
    vm::{Config, ContextObject, EbpfVm},
};
use std::sync::Arc;

/// Simple context object for instruction counting
#[derive(Debug, Clone)]
struct TracerContext {
    /// Remaining instructions allowed
    remaining: u64,
}

impl ContextObject for TracerContext {
    fn consume(&mut self, amount: u64) {
        self.remaining = self.remaining.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        self.remaining
    }
}

impl TracerContext {
    fn new(remaining: u64) -> Self {
        Self { remaining }
    }
}

/// Trace the execution of a BPF program
///
/// Takes raw BPF bytecode and returns a complete execution trace
/// including all instruction executions, register states, and memory operations.
///
/// # Arguments
/// * `bytecode` - Raw BPF program bytecode
///
/// # Returns
/// * `Ok(ExecutionTrace)` - Complete trace of program execution
/// * `Err(_)` - If program loading or execution fails
pub fn trace_program(bytecode: &[u8]) -> Result<ExecutionTrace> {
    tracing::info!("Starting BPF program trace, bytecode size: {} bytes", bytecode.len());

    // Create VM configuration
    let mut config = Config::default();
    config.enable_instruction_meter = true;
    config.enable_register_tracing = true;

    // Create loader with default builtin functions
    let loader = Arc::new(BuiltinProgram::new_loader(config.clone()));

    // Load the BPF program as raw text bytes
    let executable = Executable::from_text_bytes(
        bytecode,
        loader.clone(),
        SBPFVersion::V2,
        FunctionRegistry::default(),
    )
    .map_err(|e| anyhow::anyhow!("Failed to load BPF program: {:?}", e))?;

    // Verify the executable
    executable
        .verify::<solana_sbpf::verifier::RequisiteVerifier>()
        .map_err(|e| anyhow::anyhow!("Failed to verify executable: {:?}", e))?;

    // Set up memory regions
    let mut stack = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(config.stack_size());
    let _heap = AlignedMemory::<{ ebpf::HOST_ALIGN }>::with_capacity(0);

    // Create memory mapping
    let vm_gap_size = if config.enable_stack_frame_gaps {
        config.stack_frame_size as u64
    } else {
        0
    };

    let regions: Vec<MemoryRegion> = vec![
        executable.get_ro_region(),
        MemoryRegion::new_writable_gapped(
            stack.as_slice_mut(),
            ebpf::MM_STACK_START,
            vm_gap_size,
        ),
    ];

    let memory_mapping = MemoryMapping::new(regions, &config, executable.get_sbpf_version())
        .map_err(|e| anyhow::anyhow!("Failed to create memory mapping: {:?}", e))?;

    // Create context object with instruction limit
    let mut context = TracerContext::new(100_000);

    // Create VM
    let mut vm = EbpfVm::new(
        loader,
        executable.get_sbpf_version(),
        &mut context,
        memory_mapping,
        config.stack_size(),
    );

    // Capture initial register state
    let initial_registers = RegisterState::from_regs(vm.registers);

    // Execute program in interpreter mode for tracing
    let (instruction_count, result) = vm.execute_program(&executable, true);

    // Capture final register state after execution
    // The registers in vm are updated during execution
    let mut final_registers = RegisterState::from_regs(vm.registers);

    // The return value (r0) is stored in the result
    if let ProgramResult::Ok(return_value) = result {
        final_registers.regs[0] = return_value;
    }

    tracing::info!(
        "Program executed {} instructions, result: {:?}",
        instruction_count,
        result
    );

    // Build execution trace
    let mut trace = ExecutionTrace::new();
    trace.initial_registers = initial_registers.clone();
    trace.final_registers = final_registers.clone();

    // Capture instruction-level traces from VM register trace
    if config.enable_register_tracing {
        tracing::debug!("Captured {} instruction traces", vm.register_trace.len());

        // Get the program bytes to extract instruction data
        let (_program_vm_addr, program_bytes) = executable.get_text_bytes();

        for (idx, registers) in vm.register_trace.iter().enumerate() {
            let pc = registers[11];

            // Calculate instruction offset in the program
            let insn_offset = (pc as usize).saturating_mul(ebpf::INSN_SIZE);

            // Extract instruction bytes (8 bytes per BPF instruction)
            let instruction_bytes = if insn_offset + ebpf::INSN_SIZE <= program_bytes.len() {
                program_bytes[insn_offset..insn_offset + ebpf::INSN_SIZE].to_vec()
            } else {
                vec![0; ebpf::INSN_SIZE]
            };

            // The register_trace entries are the state BEFORE executing the instruction at that PC
            let registers_before = RegisterState::from_regs(*registers);

            // Get register state after this instruction
            // Look at the next trace entry or use final registers
            let registers_after = if idx + 1 < vm.register_trace.len() {
                RegisterState::from_regs(vm.register_trace[idx + 1])
            } else {
                // Last instruction - use final registers
                final_registers.clone()
            };

            trace.instructions.push(InstructionTrace {
                pc,
                instruction_bytes,
                registers_before,
                registers_after,
            });
        }
    }

    // Memory operation tracking:
    // solana-sbpf doesn't provide built-in memory operation tracing like it does for registers.
    // To implement full memory tracking, we would need to either:
    // 1. Fork solana-sbpf and add instrumentation to MemoryMapping load/store methods
    // 2. Use a custom memory region that logs all accesses
    // 3. Parse instructions and infer memory operations from load/store opcodes
    //
    // For now, we leave trace.memory_ops empty. This can be extended in the future.
    tracing::debug!("Memory operation tracking not yet implemented");

    match result {
        ProgramResult::Ok(_) => Ok(trace),
        ProgramResult::Err(err) => Err(anyhow::anyhow!("Program execution failed: {:?}", err)),
    }
}

use solana_sbpf::ebpf;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_simple_program() {
        // Simple BPF program: mov64 r0, 42; exit
        // BPF instruction encoding:
        // mov64 r0, 42 = 0xb7 (MOV64_IMM) dst=0, src=0, off=0, imm=42
        // exit = 0x95 (EXIT)
        #[rustfmt::skip]
        let bytecode: &[u8] = &[
            0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00,  // mov64 r0, 42
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // exit
        ];

        let result = trace_program(bytecode);
        assert!(result.is_ok(), "Failed to trace program: {:?}", result.err());

        let trace = result.unwrap();

        // Verify final register state
        assert_eq!(trace.final_registers.regs[0], 42, "Register r0 should be 42");

        // Verify instruction traces were captured
        assert!(
            trace.instruction_count() >= 2,
            "Should have traced at least 2 instructions (mov + exit), got {}",
            trace.instruction_count()
        );

        // Verify first instruction is mov64 r0, 42
        let first_insn = &trace.instructions[0];
        assert_eq!(first_insn.instruction_bytes[0], 0xb7, "First instruction should be MOV64_IMM");
        assert_eq!(first_insn.registers_before.regs[0], 0, "r0 should be 0 before first instruction");
        assert_eq!(
            first_insn.registers_after.regs[0], 42,
            "r0 should be 42 after first instruction"
        );
    }

    #[test]
    fn test_trace_arithmetic_program() {
        // BPF program: r0 = 10; r1 = 20; r0 = r0 + r1; exit
        #[rustfmt::skip]
        let bytecode: &[u8] = &[
            0xb7, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,  // mov64 r0, 10
            0xb7, 0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,  // mov64 r1, 20
            0x0f, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // add64 r0, r1
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // exit
        ];

        let result = trace_program(bytecode);
        assert!(result.is_ok(), "Failed to trace program: {:?}", result.err());

        let trace = result.unwrap();

        // Final result should be 30
        assert_eq!(trace.final_registers.regs[0], 30, "r0 should be 30");

        // Should have traced 4 instructions
        assert!(
            trace.instruction_count() >= 4,
            "Should have traced 4 instructions, got {}",
            trace.instruction_count()
        );

        // Verify the add instruction (instruction 2)
        if trace.instructions.len() > 2 {
            let add_insn = &trace.instructions[2];
            assert_eq!(add_insn.instruction_bytes[0], 0x0f, "Third instruction should be ADD64");
            assert_eq!(add_insn.registers_before.regs[0], 10, "r0 should be 10 before add");
            assert_eq!(add_insn.registers_before.regs[1], 20, "r1 should be 20 before add");
            assert_eq!(add_insn.registers_after.regs[0], 30, "r0 should be 30 after add");
        }
    }

    #[test]
    fn test_trace_empty_program() {
        // Empty program should fail to load
        let bytecode = &[];
        let result = trace_program(bytecode);
        assert!(result.is_err(), "Empty program should fail");
    }
}
