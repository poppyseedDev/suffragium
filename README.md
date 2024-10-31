# Suffragium

Suffragium is a secure, privacy-preserving voting system that combines zero-knowledge proofs (ZKP) and Fully Homomorphic Encryption (FHE) to create a trustless and tamper-resistant voting platform.

## Key Features

- **Privacy-First**: Uses FHE (powered by [Zama](https://www.zama.ai/)) to keep votes confidential while allowing encrypted vote counting
- **Secure Authentication**: Implements email-based KYC verification using DKIM signatures and zero-knowledge proofs
- **Anti-Coercion**: Prevents vote buying and voter coercion through encrypted voting
- **Quorum Support**: Configurable minimum participation requirements for vote validity
- **Transparent Results**: Automated result revelation only after voting period ends

## Technical Stack

- **Languages**: Solidity, Rust
- **Encryption**: Fully Homomorphic Encryption (FHE)
- **Authentication**: DKIM-based email verification
- **Privacy**: Zero-knowledge proofs
- **Testing**: Hardhat & Chai

## How It Works

1. Users complete KYC through email verification
2. System generates ZK proof of eligibility
3. Votes are cast using FHE for privacy
4. Encrypted votes are tallied on-chain
5. Results are revealed only after voting period ends

## Current Status

This project is under active development. We are continuously working to:

- Enhance security measures
- Improve scalability
- Add additional verification methods
- Optimize gas costs

## Contributing

Contributions are welcome! Please check our issues page or submit a pull request.

## License

MIT
