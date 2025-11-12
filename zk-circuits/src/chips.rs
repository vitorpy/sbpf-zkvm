//! BPF Instruction Chips
//!
//! Defines the trait and implementations for individual BPF instruction chips.

use halo2_base::{
    gates::GateInstructions,
    utils::ScalarField,
    AssignedValue, Context,
};
use crate::Result;

/// Trait for BPF instruction chips
///
/// Each instruction type implements this trait to define its
/// constraint system in the ZK circuit.
pub trait BpfInstructionChip<F: ScalarField> {
    /// Synthesize the constraints for this instruction
    ///
    /// This method should add all necessary constraints to prove
    /// that the instruction was executed correctly.
    ///
    /// # Arguments
    /// * `ctx` - Circuit context for assigning cells and constraints
    /// * `gate` - FlexGate for arithmetic operations
    /// * `regs_before` - Register state before instruction execution
    /// * `regs_after` - Register state after instruction execution
    ///
    /// # Returns
    /// The assigned register state after instruction execution
    fn synthesize(
        &self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        regs_before: &[AssignedValue<F>; 11],
        regs_after: &[AssignedValue<F>; 11],
    ) -> Result<()>;
}

pub mod alu64_add_imm;
pub mod alu64_add_reg;
pub mod exit;
pub mod memory;

pub use alu64_add_imm::Alu64AddImmChip;
pub use alu64_add_reg::Alu64AddRegChip;
pub use exit::ExitChip;
pub use memory::{LdwChip, StwChip};
