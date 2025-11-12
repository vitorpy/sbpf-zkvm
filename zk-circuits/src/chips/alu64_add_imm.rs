//! ALU64_ADD_IMM instruction chip
//!
//! Adds an immediate value to a 64-bit register.
//! Instruction format: dst = dst + imm (mod 2^64)

use halo2_base::{
    gates::GateInstructions,
    utils::ScalarField,
    AssignedValue, Context, QuantumCell,
};
use crate::{chips::BpfInstructionChip, Result};

/// ALU64_ADD_IMM instruction chip
///
/// Constraints:
/// 1. dst_after = dst_before + imm (mod field size)
/// 2. All other registers remain unchanged
///
/// Note: We work in the field F, which is larger than 2^64.
/// For proper 64-bit wrapping behavior, we would need range checks
/// and modular arithmetic. For this MVP, we assume values stay within
/// the field's valid range.
#[derive(Debug, Clone)]
pub struct Alu64AddImmChip {
    /// Destination register index (0-10)
    pub dst_reg: usize,
    /// Immediate value to add
    pub imm: i64,
}

impl Alu64AddImmChip {
    /// Create a new ALU64_ADD_IMM chip
    pub fn new(dst_reg: usize, imm: i64) -> Self {
        assert!(dst_reg < 11, "Invalid register index");
        Self { dst_reg, imm }
    }
}

impl<F: ScalarField> BpfInstructionChip<F> for Alu64AddImmChip {
    fn synthesize(
        &self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        regs_before: &[AssignedValue<F>; 11],
        regs_after: &[AssignedValue<F>; 11],
    ) -> Result<()> {
        // Convert immediate to field element
        // Handle signed immediate by converting to unsigned
        let imm_u64 = self.imm as u64;
        let imm_f = F::from(imm_u64);

        // Constrain: dst_after = dst_before + imm
        let dst_before = regs_before[self.dst_reg];
        let dst_after_expected = gate.add(ctx, dst_before, QuantumCell::Constant(imm_f));

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
    fn test_alu64_add_imm_chip() {
        base_test().run_gate(|ctx, gate| {
            // Create test register states
            let regs_before: [AssignedValue<Fr>; 11] = std::array::from_fn(|i| {
                ctx.load_witness(Fr::from(i as u64 * 10))
            });

            // Simulate: r1 = r1 + 42
            let dst_reg = 1;
            let imm = 42i64;
            let expected_dst = Fr::from(10u64) + Fr::from(42u64); // r1 was 10, now 10 + 42 = 52

            let regs_after: [AssignedValue<Fr>; 11] = std::array::from_fn(|i| {
                if i == dst_reg {
                    ctx.load_witness(expected_dst)
                } else {
                    ctx.load_witness(Fr::from(i as u64 * 10))
                }
            });

            let chip = Alu64AddImmChip::new(dst_reg, imm);
            chip.synthesize(ctx, gate, &regs_before, &regs_after).unwrap();
        });
    }

    #[test]
    fn test_alu64_add_imm_negative() {
        base_test().run_gate(|ctx, gate| {
            let regs_before: [AssignedValue<Fr>; 11] = std::array::from_fn(|_i| {
                ctx.load_witness(Fr::from(100u64))
            });

            // Simulate: r0 = r0 + (-5)
            let dst_reg = 0;
            let imm = -5i64;
            let imm_u64 = imm as u64;
            let expected_dst = Fr::from(100u64) + Fr::from(imm_u64); // 100 + (-5 as u64)

            let regs_after: [AssignedValue<Fr>; 11] = std::array::from_fn(|i| {
                if i == dst_reg {
                    ctx.load_witness(expected_dst)
                } else {
                    ctx.load_witness(Fr::from(100u64))
                }
            });

            let chip = Alu64AddImmChip::new(dst_reg, imm);
            chip.synthesize(ctx, gate, &regs_before, &regs_after).unwrap();
        });
    }
}
