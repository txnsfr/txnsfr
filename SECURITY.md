# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in txnsfr, please report it responsibly.

### Contact

- Email: security@txnsfr.to
- Response Time: We aim to respond within 48 hours

### Process

1. **Do not** disclose the vulnerability publicly until it has been addressed
2. Provide detailed information about the vulnerability
3. Include steps to reproduce if applicable
4. We will acknowledge receipt and work with you on a fix

### Scope

This security policy applies to:
- The txnsfr Solana program (smart contract)
- The txnsfr web application
- Related infrastructure

### Out of Scope

- Third-party dependencies (report to respective maintainers)
- Issues already reported or known
- Theoretical vulnerabilities without proof of concept

## Program Security

The txnsfr Solana program is:
- Deployed as **immutable** (no upgrade authority)
- Built with **verifiable builds** (reproducible from source)
- Open source for public audit

Program ID (Mainnet): `HV9pDozXQxZKE4CeaA5joAp4Mv9wyayEFh2gJVR9hJ9a`
Program ID (Devnet): `3D7tDvuZd1AbmGmaSZkV5jmFDysVevXTYb4G5T2RFyr5`

## Verification

You can verify the deployed program matches the source code:

```bash
# Get on-chain hash
solana-verify get-program-hash <PROGRAM_ID> -u mainnet-beta

# Get local build hash
cd anchor
anchor build --verifiable
solana-verify get-executable-hash target/verifiable/txnsfr.so
```

Hashes should match.

