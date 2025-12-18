use anchor_lang::prelude::*;

#[constant]
pub const TREE_HEIGHT: u32 = 5;
#[constant]
pub const VAULT_SEED: &[u8] = b"vault";
#[constant]
pub const MERKLE_TREE_SEED: &[u8] = b"merkle_tree";
#[constant]
pub const NULLIFIER_SEED: &[u8] = b"nullifier";
