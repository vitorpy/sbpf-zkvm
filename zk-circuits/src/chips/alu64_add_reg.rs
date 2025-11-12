//! ALU64_ADD_REG instruction chip
//!
//! Adds one register to another register.
//! Instruction format: dst = dst + src (mod 2^64)

use halo2_base::{
    gates::GateInstructions,
    utils::ScalarField,
    AssignedValue, Context,
};
use crate::{chips::BpfInstructionChip, Result};

/// ALU64_ADD_REG instruction chip
///
/// Constraints:
/// 1. dst_after = dst_before + src (mod field size)
/// 2. All other registers remain unchanged
///
/// Note: We work in the field F, which is larger than 2^64.
/// For proper 64-bit wrapping behavior, we would need range checks
/// and modular arithmetic. For this MVP, we assume values stay within
/// the field's valid range.
#[derive(Debug, Clone)]
pub struct Alu64AddRegChip {
    /// Destination register index (0-10)
    pub dst_reg: usize,
    /// Source register index (0-10)
    pub src_reg: usize,
}

impl Alu64AddRegChip {
    /// Create a new ALU64_ADD_REG chip
    pub fn new(dst_reg: usize, src_reg: usize) -> Self {
        assert!(dst_reg < 11, "Invalid destination register index");
        assert!(src_reg < 11, "Invalid source register index");
        Self { dst_reg, src_reg }
    }
}

impl<F: ScalarField> BpfInstructionChip<F> for Alu64AddRegChip {
    fn synthesize(
        &self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        regs_before: &[AssignedValue<F>; 11],
        regs_after: &[AssignedValue<F>; 11],
    ) -> Result<()> {
        // Constrain: dst_after = dst_before + src
        let dst_before = regs_before[self.dst_reg];
        let src = regs_before[self.src_reg];
        let dst_after_expected = gate.add(ctx, dst_before, src);

        // Constrain that the computed value equals the provided witness
        ctx.constrain_equal(&dst_after_expected, &regs_after[self.dst_reg]);

        // Constrain that all other registers remain unchanged
        for i in 0..11 {
            if i != self.dst_reg {
                ctx.constrain_equal(&regs_before[i], &regs_after[i]);
            }
        }

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
    fn test_alu64_add_reg_chip() {
        base_test().run_gate(|ctx, gate| {
            // Create test register states
            // r0 = 0, r1 = 10, r2 = 20, ...
            let regs_before: [AssignedValue<Fr>; 11] = std::array::from_fn(|i| {
                ctx.load_witness(Fr::from(i as u64 * 10))
            });

            // Simulate: r1 = r1 + r2 (10 + 20 = 30)
            let dst_reg = 1;
            let src_reg = 2;
            let expected_dst = Fr::from(10u64 + 20u64);

            let regs_after: [AssignedValue<Fr>; 11] = std::array::from_fn(|i| {
                if i == dst_reg {
                    ctx.load_witness(expected_dst)
                } else {
                    ctx.load_witness(Fr::from(i as u64 * 10))
                }
            });

            let chip = Alu64AddRegChip::new(dst_reg, src_reg);
            chip.synthesize(ctx, gate, &regs_before, &regs_after).unwrap();
        });
    }

    #[test]
    fn test_alu64_add_reg_same_register() {
        base_test().run_gate(|ctx, gate| {
            // Test: r3 = r3 + r3 (doubling)
            let regs_before: [AssignedValue<Fr>; 11] = std::array::from_fn(|i| {
                ctx.load_witness(Fr::from(i as u64 * 10))
            });

            let dst_reg = 3;
            let src_reg = 3;
            let expected_dst = Fr::from(30u64 + 30u64); // r3 = 30, so 30 + 30 = 60

            let regs_after: [AssignedValue<Fr>; 11] = std::array::from_fn(|i| {
                if i == dst_reg {
                    ctx.load_witness(expected_dst)
                } else {
                    ctx.load_witness(Fr::from(i as u64 * 10))
                }
            });

            let chip = Alu64AddRegChip::new(dst_reg, src_reg);
            chip.synthesize(ctx, gate, &regs_before, &regs_after).unwrap();
        });
    }
}
