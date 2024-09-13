// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {IVerifierCSCA} from "./interfaces/IVerifierCSCA.sol";
import {IProofOfPassportRegister} from "./interfaces/IProofOfPassportRegister.sol";
import {MerkleTreeRegistry} from "./MerkleTreeRegistry.sol";

/**
 * @title Proof of Passport Register Contract
 * @notice This contract is used to store the proofs of passport and verify them
 */
contract ProofOfPassportRegister is IProofOfPassportRegister, MerkleTreeRegistry {
    uint256 private immutable i_attestationId;

    mapping(uint256 => mapping(address => bool)) private s_nullifiers;
    mapping(uint256 => address) private s_verifiers;
    mapping(uint256 => address) private s_cscaVerifier;
    mapping(address => bool) private s_signers;

    constructor(
        uint256 attestationId,
        uint256 merkleRoot,
        uint256[] memory signatureAlgorithms,
        address[] memory verifiers,
        address[] memory signers
    ) MerkleTreeRegistry(merkleRoot) {
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

    function registerWithProof(
        Proof calldata proof,
        CSCAProof calldata proofCsca,
        uint256 signatureAlgorithm,
        uint256 signatureAlgorithmCsca,
        address recipient
    ) external {
        if (!checkRoot(proofCsca.merkle_root)) {
            revert ProofOfPassportRegister__InvalidMerkleRoot();
        }

        if (!s_signers[msg.sender]) {
            revert ProofOfPassportRegister__CallerNotSigner();
        }

        if (s_nullifiers[proof.nullifier][recipient]) {
            revert ProofOfPassportRegister__ProofAlreadyRegistered();
        }

        _performProofsChecks(proof, proofCsca, signatureAlgorithm, signatureAlgorithmCsca);

        s_nullifiers[proof.nullifier][recipient] = true;

        emit RecipientRegistered(recipient, proof.nullifier);
    }

    function validateProof(
        Proof calldata proof,
        CSCAProof calldata proofCsca,
        uint256 signatureAlgorithm,
        uint256 signatureAlgorithmCsca,
        address recipient
    ) external view returns (bool) {
        if (s_nullifiers[proof.nullifier][recipient] == false) {
            revert ProofOfPassportRegister__NullifierDoesNotExist();
        }

        _performProofsChecks(proof, proofCsca, signatureAlgorithm, signatureAlgorithmCsca);

        return true;
    }

    function setVerifier(uint256 signatureAlgorithm, address verifier) public onlyOwner {
        _performVerifierChecks(verifier);

        try IVerifier(verifier).verifyProof(
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0), uint256(0), uint256(0)]
        ) {} catch {
            revert ProofOfPassportRegister__InvalidVerifier();
        }

        s_verifiers[signatureAlgorithm] = verifier;

        emit VerifierSet(signatureAlgorithm, verifier);
    }

    function setCSCAVerifier(uint256 signatureAlgorithmCSCA, address cscaVerifier) public onlyOwner {
        _performVerifierChecks(cscaVerifier);

        try IVerifierCSCA(cscaVerifier).verifyProof(
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0)]
        ) {} catch {
            revert ProofOfPassportRegister__InvalidCSCAVerifier();
        }

        s_cscaVerifier[signatureAlgorithmCSCA] = cscaVerifier;

        emit CSCAVerifierSet(signatureAlgorithmCSCA, cscaVerifier);
    }

    function setSigner(address signer) public onlyOwner {
        if (signer == address(0)) {
            revert ProofOfPassportRegister__ZeroAddress();
        }

        s_signers[signer] = true;

        emit SignerSet(signer);
    }

    function removeVerifier(uint256 signatureAlgorithm) public onlyOwner {
        delete s_verifiers[signatureAlgorithm];

        emit VerifierRemoved(signatureAlgorithm);
    }

    function removeCSCAVerifier(uint256 signatureAlgorithmCSCA) public onlyOwner {
        delete s_cscaVerifier[signatureAlgorithmCSCA];

        emit CSCAVerifierRemoved(signatureAlgorithmCSCA);
    }

    function removeSigner(address signer) public onlyOwner {
        delete s_signers[signer];

        emit SignerRemoved(signer);
    }

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

    function _verifyProofCSCA(CSCAProof calldata proofCsca, uint256 signatureAlgorithmCsca)
        internal
        view
        returns (bool)
    {
        return IVerifierCSCA(s_cscaVerifier[signatureAlgorithmCsca]).verifyProof(
            proofCsca.a,
            proofCsca.b,
            proofCsca.c,
            [uint256(proofCsca.blinded_dsc_commitment), uint256(proofCsca.merkle_root)]
        );
    }

    function _performProofsChecks(
        Proof calldata proof,
        CSCAProof calldata proofCsca,
        uint256 signatureAlgorithm,
        uint256 signatureAlgorithmCsca
    ) internal view {
        if (s_verifiers[signatureAlgorithm] == address(0)) {
            revert ProofOfPassportRegister__UnsupportedSignatureAlgorithm();
        }

        if (s_cscaVerifier[signatureAlgorithmCsca] == address(0)) {
            revert ProofOfPassportRegister_UnsupportedSignatureAlgorithmCSCA();
        }

        if (proof.attestation_id != i_attestationId) {
            revert ProofOfPassportRegister__InvalidAttestationId();
        }

        if (proof.blinded_dsc_commitment != proofCsca.blinded_dsc_commitment) {
            revert ProofOfPassportRegister__BlindedDSCCommitmentDontMatch();
        }

        if (!_verifyProof(proof, signatureAlgorithm)) {
            revert ProofOfPassportRegister__InvalidProof();
        }

        if (!_verifyProofCSCA(proofCsca, signatureAlgorithmCsca)) {
            revert ProofOfPassportRegister__InvalidCSCAProof();
        }
    }

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

    function getCSCAVerifier(uint256 signatureAlgorithmCSCA) public view returns (address) {
        return s_cscaVerifier[signatureAlgorithmCSCA];
    }

    function checkIfAddressIsSigner(address signer) public view returns (bool) {
        return s_signers[signer];
    }

    function checkIfRecipientIsRegistered(uint256 nullifier, address recipient) public view returns (bool) {
        return s_nullifiers[nullifier][recipient];
    }
}
