//! Memory operation chips (LDW/STW)
//!
//! Load and store word operations for BPF memory access.

use halo2_base::{
    gates::GateInstructions,
    utils::ScalarField,
    AssignedValue, Context, QuantumCell,
};
use crate::{chips::BpfInstructionChip, Result};

/// LDW (Load Word) instruction chip
///
/// Loads a 64-bit word from memory into a register.
/// Instruction format: dst = *(u64*)(src + offset)
///
/// Constraints:
/// 1. address = src + offset
/// 2. dst_after = memory[address]
/// 3. All other registers remain unchanged
///
/// Note: In this MVP, we don't implement full memory consistency.
/// We just verify the address calculation and that the destination
/// register is updated. Full memory checking would require memory
/// trace verification.
#[derive(Debug, Clone)]
pub struct LdwChip {
    /// Destination register index (0-10)
    pub dst_reg: usize,
    /// Source register index (base address, 0-10)
    pub src_reg: usize,
    /// Offset from base address
    pub offset: i16,
    /// The value loaded from memory (witness)
    pub loaded_value: u64,
}

impl LdwChip {
    /// Create a new LDW chip
    pub fn new(dst_reg: usize, src_reg: usize, offset: i16, loaded_value: u64) -> Self {
        assert!(dst_reg < 11, "Invalid destination register index");
        assert!(src_reg < 11, "Invalid source register index");
        Self { dst_reg, src_reg, offset, loaded_value }
    }
}

impl<F: ScalarField> BpfInstructionChip<F> for LdwChip {
    fn synthesize(
        &self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        regs_before: &[AssignedValue<F>; 11],
        regs_after: &[AssignedValue<F>; 11],
    ) -> Result<()> {
        // Calculate address = src + offset
        let src = regs_before[self.src_reg];
        let offset_u64 = self.offset as u64;
        let _address = gate.add(ctx, src, QuantumCell::Constant(F::from(offset_u64)));

        // In a full implementation, we would:
        // 1. Verify address is valid
        // 2. Lookup the value in a memory trace
        // 3. Constrain dst = memory[address]
        //
        // For MVP, we just constrain that dst_after = loaded_value
        let loaded_value_f = F::from(self.loaded_value);
        let loaded_value_cell = ctx.load_witness(loaded_value_f);
        ctx.constrain_equal(&loaded_value_cell, &regs_after[self.dst_reg]);

        // Constrain that all other registers remain unchanged
        for i in 0..11 {
            if i != self.dst_reg {
                ctx.constrain_equal(&regs_before[i], &regs_after[i]);
            }
        }

        Ok(())
    }
}

/// STW (Store Word) instruction chip
///
/// Stores a 64-bit word from a register into memory.
/// Instruction format: *(u64*)(dst + offset) = src
///
/// Constraints:
/// 1. address = dst + offset
/// 2. memory[address] = src
/// 3. All registers remain unchanged (STW doesn't modify registers)
///
/// Note: In this MVP, we don't implement full memory consistency.
/// We just verify the address calculation. Full memory checking
/// would require memory trace verification.
#[derive(Debug, Clone)]
pub struct StwChip {
    /// Destination register index (base address, 0-10)
    pub dst_reg: usize,
    /// Source register index (value to store, 0-10)
    pub src_reg: usize,
    /// Offset from base address
    pub offset: i16,
}

impl StwChip {
    /// Create a new STW chip
    pub fn new(dst_reg: usize, src_reg: usize, offset: i16) -> Self {
        assert!(dst_reg < 11, "Invalid destination register index");
        assert!(src_reg < 11, "Invalid source register index");
        Self { dst_reg, src_reg, offset }
    }
}

impl<F: ScalarField> BpfInstructionChip<F> for StwChip {
    fn synthesize(
        &self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        regs_before: &[AssignedValue<F>; 11],
        regs_after: &[AssignedValue<F>; 11],
    ) -> Result<()> {
        // Calculate address = dst + offset
        let dst = regs_before[self.dst_reg];
        let offset_u64 = self.offset as u64;
        let _address = gate.add(ctx, dst, QuantumCell::Constant(F::from(offset_u64)));

        // Get the value to store
        let _src_value = regs_before[self.src_reg];

        // In a full implementation, we would:
        // 1. Verify address is valid
        // 2. Record the memory write in a memory trace
        // 3. Constrain memory[address] = src
        //
        // For MVP, we just constrain that registers don't change

        // STW doesn't modify any registers
        for i in 0..11 {
            ctx.constrain_equal(&regs_before[i], &regs_after[i]);
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
    fn test_ldw_chip() {
        base_test().run_gate(|ctx, gate| {
            // Create test register states
            // r1 = base address = 1000
            let regs_before: [AssignedValue<Fr>; 11] = std::array::from_fn(|i| {
                if i == 1 {
                    ctx.load_witness(Fr::from(1000u64))
                } else {
                    ctx.load_witness(Fr::from(i as u64 * 10))
                }
            });

            // LDW: r0 = *(r1 + 8)
            // Load value 42 from memory address 1008
            let dst_reg = 0;
            let src_reg = 1;
            let offset = 8i16;
            let loaded_value = 42u64;

            let regs_after: [AssignedValue<Fr>; 11] = std::array::from_fn(|i| {
                if i == dst_reg {
                    ctx.load_witness(Fr::from(loaded_value))
                } else if i == 1 {
                    ctx.load_witness(Fr::from(1000u64))
                } else {
                    ctx.load_witness(Fr::from(i as u64 * 10))
                }
            });

            let chip = LdwChip::new(dst_reg, src_reg, offset, loaded_value);
            chip.synthesize(ctx, gate, &regs_before, &regs_after).unwrap();
        });
    }

    #[test]
    fn test_stw_chip() {
        base_test().run_gate(|ctx, gate| {
            // Create test register states
            // r1 = base address = 2000
            // r2 = value to store = 99
            let regs_before: [AssignedValue<Fr>; 11] = std::array::from_fn(|i| {
                if i == 1 {
                    ctx.load_witness(Fr::from(2000u64))
                } else if i == 2 {
                    ctx.load_witness(Fr::from(99u64))
                } else {
                    ctx.load_witness(Fr::from(i as u64 * 10))
                }
            });

            // STW: *(r1 + 16) = r2
            // Store value from r2 to memory address 2016
            let dst_reg = 1;
            let src_reg = 2;
            let offset = 16i16;

            // STW doesn't modify registers
            let regs_after: [AssignedValue<Fr>; 11] = std::array::from_fn(|i| {
                if i == 1 {
                    ctx.load_witness(Fr::from(2000u64))
                } else if i == 2 {
                    ctx.load_witness(Fr::from(99u64))
                } else {
                    ctx.load_witness(Fr::from(i as u64 * 10))
                }
            });

            let chip = StwChip::new(dst_reg, src_reg, offset);
            chip.synthesize(ctx, gate, &regs_before, &regs_after).unwrap();
        });
    }
}
