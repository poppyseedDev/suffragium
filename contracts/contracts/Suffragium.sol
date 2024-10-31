// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import "fhevm/lib/TFHE.sol";
import { GatewayCaller, Gateway } from "fhevm/gateway/GatewayCaller.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IdentityManager } from "./IdentityManager.sol";
import { ISuffragium } from "./interfaces/ISuffragium.sol";

/**
 * @title Suffragium
 * @dev A voting system contract that uses FHE (Fully Homomorphic Encryption) to enable private voting
 * while maintaining vote integrity and preventing manipulation.
 */
contract Suffragium is ISuffragium, IdentityManager, GatewayCaller, Ownable {
    // Encrypted value representing 1, used for vote counting
    euint64 internal ENC_ONE;

    // Mapping of vote IDs to Vote structs containing vote details
    mapping(uint256 => Vote) public votes;
    // Double mapping tracking which voters have cast votes for each vote ID
    mapping(uint256 => mapping(bytes32 => bool)) private _castedVotes;
    // Counter for generating unique vote IDs
    uint256 private _nextVoteId;

    /**
     * @dev Constructor initializes the contract with required parameters
     * @param verifier Address of the proof verifier contract
     * @param programVKey Verification key for the zero-knowledge program
     * @param emailPublicKeyHash Hash of the email public key for voter verification
     * @param fromDomainHash Hash of the allowed email domain
     */
    constructor(
        address verifier,
        bytes32 programVKey,
        bytes32 emailPublicKeyHash,
        bytes32 fromDomainHash
    ) IdentityManager(verifier, programVKey, emailPublicKeyHash, fromDomainHash) Ownable(msg.sender) {
        ENC_ONE = TFHE.asEuint64(1);
        TFHE.allow(ENC_ONE, address(this));
    }

    /// @inheritdoc ISuffragium
    function createVote(uint256 endBlock, uint256 minQuorum, string calldata description) external onlyOwner {
        uint256 voteId = _nextVoteId;
        votes[voteId] = Vote(
            endBlock,
            minQuorum,
            TFHE.asEuint64(0),
            TFHE.asEuint64(0),
            0,
            0,
            description,
            VoteState.Created
        );
        TFHE.allow(votes[voteId].encryptedResult, address(this));
        TFHE.allow(votes[voteId].encryptedValidVotes, address(this));
        _nextVoteId++;
        emit VoteCreated(voteId);
    }

    /// @inheritdoc ISuffragium
    function castVote(
        uint256 voteId,
        einput encryptedSupport,
        bytes calldata supportProof,
        bytes calldata identityPublicValues,
        bytes calldata identityProofBytes
    ) external {
        // NOTE: If an attacker gains access to the email, they can generate a proof and submit it on-chain with a support value greater than 1, resulting in censorship of the legitimate voter.
        bytes32 voterId = verifyProofAndGetVoterId(identityPublicValues, identityProofBytes);
        if (_castedVotes[voteId][voterId]) revert AlreadyVoted();
        _castedVotes[voteId][voterId] = true;

        Vote storage vote = _getVote(voteId);
        if (block.number > vote.endBlock) revert VoteClosed();

        // Convert and validate the encrypted vote
        euint64 support = TFHE.asEuint64(encryptedSupport, supportProof);
        TFHE.allowTransient(support, address(this));
        ebool isValid = TFHE.le(support, ENC_ONE);
        TFHE.allowTransient(isValid, address(this));

        // Update vote tallies if vote is valid
        euint64 encryptedResult = vote.encryptedResult;
        euint64 encryptedValidVotes = vote.encryptedValidVotes;
        vote.encryptedResult = TFHE.select(isValid, TFHE.add(support, encryptedResult), encryptedResult);
        vote.encryptedValidVotes = TFHE.select(isValid, TFHE.add(encryptedValidVotes, ENC_ONE), encryptedValidVotes);
        TFHE.allow(vote.encryptedResult, address(this));
        TFHE.allow(vote.encryptedValidVotes, address(this));

        emit VoteCasted(voteId);
    }

    /// @inheritdoc ISuffragium
    function getVote(uint256 voteId) external view returns (Vote memory) {
        return _getVote(voteId);
    }

    /// @inheritdoc ISuffragium
    function hasVoted(uint256 voteId, bytes32 voterId) external view returns (bool) {
        return _castedVotes[voteId][voterId];
    }

    /// @inheritdoc ISuffragium
    function isVotePassed(uint256 voteId) external view returns (bool) {
        Vote storage vote = _getVote(voteId);
        if (vote.state != VoteState.Revealed) return false;
        return (vote.result * 10 ** 18) / vote.validVotes >= vote.minQuorum;
    }

    /// @inheritdoc ISuffragium
    function requestRevealVote(uint256 voteId) external {
        Vote storage vote = _getVote(voteId);
        if (block.number <= vote.endBlock) revert VoteNotClosed();

        // Request decryption of vote results through the Gateway
        uint256[] memory cts = new uint256[](2);
        cts[0] = Gateway.toUint256(vote.encryptedResult);
        cts[1] = Gateway.toUint256(vote.encryptedValidVotes);
        uint256 requestId = Gateway.requestDecryption(cts, this.revealVote.selector, 0, block.timestamp + 100, false);
        addParamsUint256(requestId, voteId);
        vote.state = VoteState.RequestedToReveal;

        emit VoteRevealRequested(voteId);
    }

    /// @inheritdoc ISuffragium
    function revealVote(uint256 requestId, uint256 result, uint256 validVotes) external onlyGateway {
        uint256[] memory params = getParamsUint256(requestId);
        uint256 voteId = params[0];

        // Update vote with decrypted results
        Vote storage vote = _getVote(voteId);
        vote.state = VoteState.Revealed;
        vote.result = result;
        vote.validVotes = validVotes;

        emit VoteRevealed(voteId);
    }

    /**
     * @dev Internal helper to retrieve a vote by ID and validate its existence
     * @param voteId ID of the vote to retrieve
     * @return Vote storage pointer to the vote data
     */
    function _getVote(uint256 voteId) internal view returns (Vote storage) {
        Vote storage vote = votes[voteId];
        if (vote.endBlock == 0) revert VoteDoesNotExist();
        return vote;
    }
}
