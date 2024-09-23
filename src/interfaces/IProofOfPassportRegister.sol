// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IProofOfPassportRegister {
    /**
     * Errors
     */
    error ProofOfPassportRegister__ZeroAddress();

    error ProofOfPassportRegister__UnsupportedSignatureAlgorithm();

    error ProofOfPassportRegister_UnsupportedSignatureAlgorithmCSCA();

    error ProofOfPassportRegister__InvalidAttestationId();

    error ProofOfPassportRegister__InvalidProof();

    error ProofOfPassportRegister__InvalidCSCAProof();

    error ProofOfPassportRegister__BlindedDSCCommitmentDontMatch();

    error ProofOfPassportRegister__InvalidMerkleRoot();

    error ProofOfPassportRegister__InvalidLength();

    error ProofOfPassportRegister__CscaInvalidLength();

    error ProofOfPassportRegister__ProofAlreadyRegistered();

    error ProofOfPassportRegister__CallerNotSigner();

    error ProofOfPassportRegister__InvalidSigner();

    error ProofOfPassportRegister__NullifierDoesNotExist();

    error ProofOfPassportRegister__NotAContract();

    error ProofOfPassportRegister__InvalidVerifier();

    error ProofOfPassportRegister__InvalidCSCAVerifier();

    /**
     * Type declarations
     */
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
        uint256 blinded_dsc_commitment;
        uint256 nullifier;
        uint256 commitment;
        uint256 attestation_id;
    }

    struct CSCAProof {
        uint256 blinded_dsc_commitment;
        uint256 merkle_root;
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    /**
     * Events
     */
    event RecipientRegistered(address indexed recipient, uint256 indexed nullifier);

    event VerifierSet(uint256 indexed signature_algorithm, address indexed verifier);

    event CSCAVerifierSet(uint256 indexed signature_algorithm, address indexed verifier);

    event SignerSet(address indexed signer);

    event SignerRemoved(address indexed signer);

    event VerifierRemoved(uint256 indexed signature_algorithm);

    event CSCAVerifierRemoved(uint256 indexed signature_algorithm);

    /**
     * Functions
     */
    function registerWithProof(
        Proof calldata proof,
        CSCAProof calldata proofCsca,
        uint256 signatureAlgorithm,
        uint256 signatureAlgorithmCsca,
        address recipient
    ) external;

    function validateProof(
        Proof calldata proof,
        CSCAProof calldata proofCsca,
        uint256 signatureAlgorithm,
        uint256 signatureAlgorithmCsca,
        address recipient
    ) external view returns (bool);

    function setVerifier(uint256 signatureAlgorithm, address verifier) external;

    function setCSCAVerifier(uint256 signatureAlgorithmCSCA, address cscaVerifier) external;

    function setSigner(address signer) external;

    function removeVerifier(uint256 signatureAlgorithm) external;

    function removeSigner(address signer) external;

    function removeCSCAVerifier(uint256 signatureAlgorithmCSCA) external;

    function getAttestationId() external view returns (uint256);

    function isRegistered(uint256 nullifier, address recipient) external view returns (bool);

    function getVerifier(uint256 signatureAlgorithm) external view returns (address);

    function getCSCAVerifier(uint256 signatureAlgorithm) external view returns (address);

    function checkIfAddressIsSigner(address signer) external view returns (bool);

    function checkIfRecipientIsRegistered(uint256 nullifier, address recipient) external view returns (bool);
}
