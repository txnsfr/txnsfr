# txnsfr

Privacy as infrastructure, built on Solana.

**txnsfr** enables private asset transfers via an immutable on-chain Anchor program, combined with private file transfers utilizing the Irys datachain.

## Features

### Private SOL Transfers
- **Zero-Knowledge Proofs**: Transfer SOL privately using Groth16 ZK proofs on BN254
- **On-Chain Privacy Pool**: Break the link between sender and receiver wallet addresses
- **UTXO Model**: Unspent transaction outputs with Poseidon hash commitments
- **26-Level Merkle Tree**: Supports 67+ million private transactions
- **Immutable Program**: Deployed with no upgrade authority - trustless by design

### Private File Transfers
- **Irys Datachain Integration**: Permanent, decentralized file storage
- **End-to-End Encryption**: Files encrypted before upload
- **Private Retrieval**: Claim files using ZK proofs without revealing identity

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        txnsfr                               │
├─────────────────────────────────────────────────────────────┤
│  Private SOL Transfers          │  Private File Transfers   │
│  ─────────────────────          │  ──────────────────────   │
│  • Deposit SOL → commitment     │  • Upload encrypted file  │
│  • Claim with ZK proof          │  • Store on Irys          │
│  • No address linkage           │  • Claim with ZK proof    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Solana Program                           │
│  • Groth16 verification (on-chain)                          │
│  • Sparse Merkle tree with 100 root history                 │
│  • Nullifier tracking (prevents double-spend)               │
│  • Immutable deployment                                     │
└─────────────────────────────────────────────────────────────┘
```

## Repository Structure

```
├── anchor/           # Solana program (Anchor framework)
│   └── programs/txnsfr/src/
│       ├── lib.rs          # Main program logic
│       ├── groth16.rs      # ZK proof verification
│       ├── merkle_tree.rs  # Sparse Merkle tree
│       └── utils.rs        # Verifying key & utilities
├── circuits/         # Circom ZK circuits
│   ├── transaction.circom   # Main transaction circuit
│   ├── transaction2.circom  # Entry point (26 levels, 2 inputs, 2 outputs)
│   ├── merkleProof.circom   # Merkle proof verification
│   └── keypair.circom       # Key derivation
└── SECURITY.md       # Security policy
```

## Governance

The txnsfr program is deployed as **immutable** — it cannot be upgraded or modified by anyone, including the development team.

In the event that a redeployment becomes necessary due to:
- Solana blockchain updates requiring program changes
- Community-proposed feature enhancements  
- Unforeseen security issues

**Any new program deployment will only occur through a governance vote by $TXNSFR token holders.**

### Redeployment Process

1. **Proposal**: A governance proposal is submitted describing the changes
2. **Review Period**: Token holders review the proposed code (published to this repository)
3. **Vote**: Quorum of token holders must approve the new deployment
4. **Migration**: Upon approval, a new immutable program is deployed with updated program ID
5. **Transition**: Users migrate funds at their discretion; old program remains functional

This ensures the protocol remains community-governed and no single party can unilaterally modify the system.

## Security

- **Immutable**: Program deployed with `--final` flag, no upgrade authority
- **Verifiable Build**: Source code matches on-chain bytecode
- **Security.txt**: Embedded contact information per Solana standards

Report vulnerabilities to: security@txnsfr.to

## License

MIT
