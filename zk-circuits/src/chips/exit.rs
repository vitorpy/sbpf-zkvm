//! EXIT instruction chip
//!
//! Terminates BPF program execution.
//! The return value is stored in r0.

use halo2_base::{
    gates::GateInstructions,
    utils::ScalarField,
    AssignedValue, Context,
};
use crate::{chips::BpfInstructionChip, Result};

/// EXIT instruction chip
///
/// Constraints:
/// 1. All registers remain unchanged (EXIT doesn't modify registers)
/// 2. r0 contains the return value
///
/// This is the simplest chip - it just verifies that the program
/// can terminate cleanly without modifying any register state.
#[derive(Debug, Clone)]
pub struct ExitChip;

impl ExitChip {
    /// Create a new EXIT chip
    pub fn new() -> Self {
        Self
    }
}

impl Default for ExitChip {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: ScalarField> BpfInstructionChip<F> for ExitChip {
    fn synthesize(
        &self,
        ctx: &mut Context<F>,
        _gate: &impl GateInstructions<F>,
        regs_before: &[AssignedValue<F>; 11],
        regs_after: &[AssignedValue<F>; 11],
    ) -> Result<()> {
        // EXIT instruction doesn't modify any registers
        // Just constrain that all registers remain the same
        for i in 0..11 {
            ctx.constrain_equal(&regs_before[i], &regs_after[i]);
        }

        // Note: In a real implementation, we might want to:
        // 1. Verify this is the last instruction in the trace
        // 2. Expose r0 (return value) as a public output
        // For this MVP, we keep it simple.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::{
        utils::testing::base_test,
        halo2_proofs::halo2curves::bn256::Fr,
    };

    #[test]
    fn test_exit_chip() {
        base_test().run_gate(|ctx, gate| {
            // Create test register states with r0 = 42 (return value)
            let regs_before: [AssignedValue<Fr>; 11] = std::array::from_fn(|i| {
                if i == 0 {
                    ctx.load_witness(Fr::from(42u64)) // r0 = return value
                } else {
                    ctx.load_witness(Fr::from(i as u64 * 10))
                }
            });

            // EXIT doesn't modify registers
            let regs_after: [AssignedValue<Fr>; 11] = std::array::from_fn(|i| {
                if i == 0 {
                    ctx.load_witness(Fr::from(42u64))
                } else {
                    ctx.load_witness(Fr::from(i as u64 * 10))
                }
            });

            let chip = ExitChip::new();
            chip.synthesize(ctx, gate, &regs_before, &regs_after).unwrap();
        });
    }
}
