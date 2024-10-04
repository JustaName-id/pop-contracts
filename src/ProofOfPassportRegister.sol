// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {IProofOfPassportRegister} from "./interfaces/IProofOfPassportRegister.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title Proof of Passport Register Contract
 * @notice This contract is used to store the proofs of passport and verify them
 * @author JustaLab
 */
contract ProofOfPassportRegister is IProofOfPassportRegister, Ownable {
    uint256 private immutable i_attestationId;

    mapping(uint256 => mapping(address => bool)) private s_nullifiers;
    mapping(uint256 signatureAlgorithm => address) private s_verifiers;
    mapping(address => bool) private s_signers;

    /**
     * @param caller The caller address to check
     * @notice Throws if the caller is not a registered signer
     * @dev This modifier is used to check if the caller is a registered signer
     */
    modifier onlySigner(address caller) {
        if (!s_signers[caller]) {
            revert ProofOfPassportRegister__CallerNotSigner();
        }
        _;
    }

    constructor(
        uint256 attestationId,
        uint256[] memory signatureAlgorithms,
        address[] memory verifiers,
        address[] memory signers
    ) Ownable(msg.sender) {
        if (signatureAlgorithms.length != verifiers.length) {
            revert ProofOfPassportRegister__InvalidLength();
        }

        for (uint256 i = 0; i < signatureAlgorithms.length; i++) {
            setVerifier(signatureAlgorithms[i], verifiers[i]);
        }

        for (uint256 i = 0; i < signers.length; i++) {
            setSigner(signers[i]);
        }

        i_attestationId = attestationId;
    }

    /**
     * @notice Register a recipient after checking if provided proofs are valid
     * @param proof The proof to verify
     * @param signatureAlgorithm The signature algorithm used to sign the proof
     * @param recipient The recipient to register
     * @dev Only registered signers can call this function
     */
    function registerWithProof(Proof calldata proof, uint256 signatureAlgorithm, address recipient)
        external
        onlySigner(msg.sender)
    {
        if (s_nullifiers[proof.nullifier][recipient]) {
            revert ProofOfPassportRegister__ProofAlreadyRegistered();
        }

        _performProofsChecks(proof, signatureAlgorithm);

        s_nullifiers[proof.nullifier][recipient] = true;

        emit RecipientRegistered(recipient, proof.nullifier);
    }

    /**
     * @notice Validates a proof
     * @param proof The proof to validate
     * @param signatureAlgorithm The signature algorithm used to sign the proof
     * @param recipient The recipient to validate
     * @return true if the proof is valid
     * @dev This function will first check if the nullifier exists and then perform the proof checks
     */
    function validateProof(Proof calldata proof, uint256 signatureAlgorithm, address recipient)
        external
        view
        returns (bool)
    {
        if (s_nullifiers[proof.nullifier][recipient] == false) {
            revert ProofOfPassportRegister__NullifierDoesNotExist();
        }

        _performProofsChecks(proof, signatureAlgorithm);

        return true;
    }

    /**
     * @notice Sets a new verifier address
     * @param signatureAlgorithm The signature algorithm associated with the verifier
     * @param verifier The new verifier address to set
     * @dev This function is used to set a new verifier address.
     *      It will check if the verifier address by first calling the _performVerifierChecks function.
     *      It will also check if the verifier address is valid by calling the verifyProof function of the verifier contract
     */
    function setVerifier(uint256 signatureAlgorithm, address verifier) public onlyOwner {
        _performVerifierChecks(verifier);

        try IVerifier(verifier).verifyProof(
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            [
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0),
                uint256(0)
            ]
        ) {} catch {
            revert ProofOfPassportRegister__InvalidVerifier();
        }

        s_verifiers[signatureAlgorithm] = verifier;

        emit VerifierSet(signatureAlgorithm, verifier);
    }

    /**
     * @notice Adds new signer
     * @param signer The new signer address to add
     * @dev Only the owner can call this function
     */
    function setSigner(address signer) public onlyOwner {
        if (signer == address(0)) {
            revert ProofOfPassportRegister__ZeroAddress();
        }

        s_signers[signer] = true;

        emit SignerSet(signer);
    }

    /**
     * @notice Removes a verifier address
     * @param signatureAlgorithm The signature algorithm associated with the verifier to remove
     * @dev Only the owner can call this function
     */
    function removeVerifier(uint256 signatureAlgorithm) public onlyOwner {
        delete s_verifiers[signatureAlgorithm];

        emit VerifierRemoved(signatureAlgorithm);
    }

    /**
     * @notice Removes a signer address
     * @param signer The signer address to remove
     * @dev Only the owner can call this function
     */
    function removeSigner(address signer) public onlyOwner {
        delete s_signers[signer];

        emit SignerRemoved(signer);
    }

    /**
     * @notice Verifies the provided proof using the specified signature algorithm by invoking the verifier contract.
     * @param proof The proof data containing cryptographic components (a, b, c) and commitments.
     * @param signatureAlgorithm The signature algorithm used to verify the proof.
     * @return bool Returns `true` if the proof is valid, `false` otherwise.
     * @notice This function performs the following:
     *         - Retrieves the verifier contract for the provided `signatureAlgorithm`.
     *         - Calls the verifier contract's `verifyProof` function, passing the proof's cryptographic components and
     *           commitments (blinded DSC commitment, nullifier, commitment, and attestation ID).
     * @dev Reverts if the verifier contract is not set for the specified `signatureAlgorithm`.
     */
    function _verifyProof(Proof calldata proof, uint256 signatureAlgorithm) internal view returns (bool) {
        return IVerifier(s_verifiers[signatureAlgorithm]).verifyProof(
            proof.a,
            proof.b,
            proof.c,
            [
                uint256(proof.blinded_dsc_commitment),
                uint256(proof.nullifier),
                uint256(proof.commitment),
                uint256(proof.attestation_id)
            ]
        );
    }

    /**
     * @notice Performs various checks on the provided proof and CSCA (Card Security Certificate Authority) proof to ensure
     *      their validity and compatibility with the system's requirements.
     * @param proof The proof data containing attestation information to verify.
     * @param signatureAlgorithm The signature algorithm used for verifying the attestation proof.
     * @dev This function verifies the following conditions:
     *         - The provided `signatureAlgorithm` is supported by the system.
     *         - The provided `signatureAlgorithmCsca` is supported for CSCA verification.
     *         - The `attestation_id` in the proof matches the expected attestation ID.
     *         - The `proof` provided is valid and verifiable using the specified `signatureAlgorithm`.
     */
    function _performProofsChecks(Proof calldata proof, uint256 signatureAlgorithm) internal view {
        if (s_verifiers[signatureAlgorithm] == address(0)) {
            revert ProofOfPassportRegister__UnsupportedSignatureAlgorithm();
        }

        if (proof.attestation_id != i_attestationId) {
            revert ProofOfPassportRegister__InvalidAttestationId();
        }

        if (!_verifyProof(proof, signatureAlgorithm)) {
            revert ProofOfPassportRegister__InvalidProof();
        }
    }

    /**
     * @param verifierAddress The verifier address to check
     * @notice Meant to check if the verifier address is valid. It shouldn't be a zero address and should be a contract address.
     * @dev This function is used to check if the verifier address is valid.
     *         It is meant to be used in the setVerifier and setCSCAVerifier functions
     */
    function _performVerifierChecks(address verifierAddress) internal view {
        if (verifierAddress == address(0)) {
            revert ProofOfPassportRegister__ZeroAddress();
        }

        uint32 size;
        assembly {
            size := extcodesize(verifierAddress)
        }
        if (size == 0) {
            revert ProofOfPassportRegister__NotAContract();
        }
    }

    /**
     * Getter Functions
     */
    function getAttestationId() public view returns (uint256) {
        return i_attestationId;
    }

    function isRegistered(uint256 nullifier, address recipient) public view returns (bool) {
        return s_nullifiers[nullifier][recipient];
    }

    function getVerifier(uint256 signatureAlgorithm) public view returns (address) {
        return s_verifiers[signatureAlgorithm];
    }

    function checkIfAddressIsSigner(address signer) public view returns (bool) {
        return s_signers[signer];
    }
}
