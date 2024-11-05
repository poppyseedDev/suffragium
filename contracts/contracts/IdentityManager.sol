// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import { ISP1Verifier } from "./interfaces/ISP1Verifier.sol";
import { IIdentityManager } from "./interfaces/IIdentityManager.sol";

/**
 * @title IdentityManager
 * @notice Manages voter identity verification using DKIM email signatures
 * @dev Uses zero-knowledge proofs to verify email authenticity while preserving privacy
 */
contract IdentityManager is IIdentityManager {
    /// @notice Address of the SP1 zero-knowledge proof verifier contract
    address public immutable VERIFIER;

    /// @notice Verification key for the zero-knowledge program
    bytes32 public immutable PROGRAM_V_KEY;

    /// @notice Hash of the expected DKIM public key for email verification
    bytes32 public immutable EMAIL_PUBLIC_KEY_HASH;

    /// @notice Hash of the expected email sender domain
    bytes32 public immutable FROM_DOMAIN_HASH;

    /**
     * @notice Initializes the identity manager with verification parameters
     * @param verifier Address of the SP1 verifier contract
     * @param programVKey Verification key for the ZK program
     * @param emailPublicKeyHash Hash of the DKIM public key
     * @param fromDomainHash Hash of the sender domain
     */
    constructor(address verifier, bytes32 programVKey, bytes32 emailPublicKeyHash, bytes32 fromDomainHash) {
        VERIFIER = verifier;
        PROGRAM_V_KEY = programVKey;
        EMAIL_PUBLIC_KEY_HASH = emailPublicKeyHash;
        FROM_DOMAIN_HASH = fromDomainHash;
    }

    /// @inheritdoc IIdentityManager
    function verifyProofAndGetVoterId(
        bytes calldata identityPublicValues,
        bytes calldata identityProofBytes
    ) public view returns (bytes32) {
        // TODO: use identityPublicValues and identityProofBytes
        ISP1Verifier(VERIFIER).verifyProof(PROGRAM_V_KEY, abi.encodePacked(""), abi.encodePacked(""));

        // Decode the public values committed by the ZK program
        (bytes32 fromDomainHash, bytes32 emailPublicKeyHash, bytes32 voterId, bool verified) = abi.decode(
            identityPublicValues,
            (bytes32, bytes32, bytes32, bool)
        );

        // Verify the DKIM signature was valid
        if (!verified) revert DkimSignatureVerificationFailed();

        // Verify the email used the expected DKIM public key
        if (emailPublicKeyHash != EMAIL_PUBLIC_KEY_HASH) revert InvalidEmailPublicKeyHash();

        // Verify the email came from the expected domain
        if (fromDomainHash != FROM_DOMAIN_HASH) revert InvalidFromDomainHash();

        return voterId;
    }
}
