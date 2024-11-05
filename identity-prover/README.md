# Email Identity Prover

A zero-knowledge proof system that verifies email authenticity using DKIM signatures while preserving privacy.

## Overview

This system consists of two main components:

### 1. Script (`/script`)

A Rust script that:

- Takes an email file and expected sender domain as input
- Validates DKIM signatures in the email
- Retrieves the DKIM public key from DNS
- Generates a zero-knowledge proof that the email is authentically signed
- Saves the proof to `proof.json`

### 2. Program (`/program`)

A RISC-V program that runs inside the zero-knowledge virtual machine and:

- Verifies the DKIM signature of the email
- Commits three privacy-preserving hashes as public values:
  - Hash of the sender's domain
  - Hash of the DKIM public key
  - Hash of the recipient's email address (voter ID)
- Commits a boolean indicating successful DKIM verification

## How It Works

1. The script reads an email file and extracts DKIM headers
2. It verifies the signing domain matches the expected domain
3. The DKIM public key is retrieved from DNS
4. All data is passed to the zero-knowledge program
5. The program verifies the signature and produces commitments
6. The script generates and verifies a proof of this computation
