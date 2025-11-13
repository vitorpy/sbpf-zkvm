//! Data structures for execution traces

use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;

/// Complete execution trace of a BPF program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    /// Vector of instruction traces in execution order
    pub instructions: Vec<InstructionTrace>,
    /// Account state changes during execution
    pub account_states: Vec<AccountStateChange>,
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

/// Solana account state with all account fields
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountState {
    /// Account public key (address)
    pub pubkey: Pubkey,
    /// Account balance in lamports
    pub lamports: u64,
    /// Account data bytes
    pub data: Vec<u8>,
    /// Program that owns this account
    pub owner: Pubkey,
    /// Whether the account is executable
    pub executable: bool,
    /// Epoch at which this account will next owe rent
    pub rent_epoch: u64,
}

/// Captures state changes for a single account during execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStateChange {
    /// Account public key
    pub pubkey: Pubkey,
    /// State before execution
    pub before: AccountState,
    /// State after execution
    pub after: AccountState,
}

impl AccountState {
    /// Create a new account state
    pub fn new(
        pubkey: Pubkey,
        lamports: u64,
        data: Vec<u8>,
        owner: Pubkey,
        executable: bool,
        rent_epoch: u64,
    ) -> Self {
        Self {
            pubkey,
            lamports,
            data,
            owner,
            executable,
            rent_epoch,
        }
    }

    /// Create an empty account state with given pubkey
    pub fn empty(pubkey: Pubkey) -> Self {
        Self {
            pubkey,
            lamports: 0,
            data: Vec::new(),
            owner: Pubkey::default(),
            executable: false,
            rent_epoch: 0,
        }
    }
}

impl AccountStateChange {
    /// Create a new account state change
    pub fn new(pubkey: Pubkey, before: AccountState, after: AccountState) -> Self {
        Self {
            pubkey,
            before,
            after,
        }
    }

    /// Check if the account data changed
    pub fn data_changed(&self) -> bool {
        self.before.data != self.after.data
    }

    /// Check if the account lamports changed
    pub fn lamports_changed(&self) -> bool {
        self.before.lamports != self.after.lamports
    }
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
            account_states: Vec::new(),
            initial_registers: RegisterState::new(),
            final_registers: RegisterState::new(),
        }
    }

    /// Get number of instructions executed
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Get number of account state changes
    pub fn account_change_count(&self) -> usize {
        self.account_states.len()
    }
}

impl Default for ExecutionTrace {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_state_new() {
        let pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let data = vec![1, 2, 3, 4];

        let account = AccountState::new(
            pubkey,
            1000,
            data.clone(),
            owner,
            false,
            42,
        );

        assert_eq!(account.pubkey, pubkey);
        assert_eq!(account.lamports, 1000);
        assert_eq!(account.data, data);
        assert_eq!(account.owner, owner);
        assert_eq!(account.executable, false);
        assert_eq!(account.rent_epoch, 42);
    }

    #[test]
    fn test_account_state_empty() {
        let pubkey = Pubkey::new_unique();
        let account = AccountState::empty(pubkey);

        assert_eq!(account.pubkey, pubkey);
        assert_eq!(account.lamports, 0);
        assert_eq!(account.data.len(), 0);
        assert_eq!(account.owner, Pubkey::default());
        assert_eq!(account.executable, false);
        assert_eq!(account.rent_epoch, 0);
    }

    #[test]
    fn test_account_state_change() {
        let pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let before = AccountState::new(
            pubkey,
            1000,
            vec![0, 0, 0, 0],
            owner,
            false,
            0,
        );

        let after = AccountState::new(
            pubkey,
            1000,
            vec![1, 0, 0, 0],
            owner,
            false,
            0,
        );

        let change = AccountStateChange::new(pubkey, before.clone(), after.clone());

        assert_eq!(change.pubkey, pubkey);
        assert_eq!(change.before, before);
        assert_eq!(change.after, after);
        assert!(change.data_changed());
        assert!(!change.lamports_changed());
    }

    #[test]
    fn test_account_state_change_lamports() {
        let pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let before = AccountState::new(
            pubkey,
            1000,
            vec![0, 0, 0, 0],
            owner,
            false,
            0,
        );

        let after = AccountState::new(
            pubkey,
            2000,
            vec![0, 0, 0, 0],
            owner,
            false,
            0,
        );

        let change = AccountStateChange::new(pubkey, before, after);

        assert!(!change.data_changed());
        assert!(change.lamports_changed());
    }

    #[test]
    fn test_execution_trace_new() {
        let trace = ExecutionTrace::new();

        assert_eq!(trace.instruction_count(), 0);
        assert_eq!(trace.account_change_count(), 0);
    }

    #[test]
    fn test_execution_trace_with_accounts() {
        let mut trace = ExecutionTrace::new();

        let pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let before = AccountState::new(pubkey, 1000, vec![0], owner, false, 0);
        let after = AccountState::new(pubkey, 1000, vec![1], owner, false, 0);

        trace.account_states.push(AccountStateChange::new(pubkey, before, after));

        assert_eq!(trace.account_change_count(), 1);
    }

    #[test]
    fn test_serialization() {
        let pubkey = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        let account = AccountState::new(
            pubkey,
            1000,
            vec![1, 2, 3],
            owner,
            false,
            42,
        );

        // Test serialization round-trip
        let json = serde_json::to_string(&account).unwrap();
        let deserialized: AccountState = serde_json::from_str(&json).unwrap();

        assert_eq!(account, deserialized);
    }
}
