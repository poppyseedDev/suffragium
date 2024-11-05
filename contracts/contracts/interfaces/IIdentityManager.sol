// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

/// @title IdentityManager Interface
/// @author Alessandro Manfredi
/// @notice This contract is the interface for the IdentityManager contract.
interface IIdentityManager {
    error DkimSignatureVerificationFailed();
    error InvalidEmailPublicKeyHash();
    error InvalidFromDomainHash();

    function verifyProofAndGetVoterId(
        bytes calldata identityPublicValues,
        bytes calldata identityProofBytes
    ) external view returns (bytes32);
}
