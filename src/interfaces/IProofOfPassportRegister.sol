// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IProofOfPassportRegister {
    /**
     * Errors
     */
    error ProofOfPassportRegister__ZeroAddress();

    error ProofOfPassportRegister__UnsupportedSignatureAlgorithm();

    error ProofOfPassportRegister__InvalidProof();

    error ProofOfPassportRegister__InvalidLength();

    error ProofOfPassportRegister__ProofAlreadyRegistered();

    error ProofOfPassportRegister__CallerNotSigner();

    error ProofOfPassportRegister__InvalidSigner();

    error ProofOfPassportRegister__NullifierDoesNotExist();

    error ProofOfPassportRegister__NotAContract();

    error ProofOfPassportRegister__InvalidVerifier();

    /**
     * Type declarations
     */
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
        uint256[45] pubSignals;
    }

    /**
     * Events
     */
    event RecipientRegistered(address indexed recipient, uint256 indexed nullifier);

    event VerifierSet(uint256 indexed signature_algorithm, address indexed verifier);

    event SignerSet(address indexed signer);

    event SignerRemoved(address indexed signer);

    event VerifierRemoved(uint256 indexed signature_algorithm);

    /**
     * Functions
     */
    function registerWithProof(Proof calldata proof, address recipient) external;

    function validateProof(Proof calldata proof, address recipient) external view returns (bool);

    function setVerifier(uint256 signatureAlgorithm, address verifier, uint256 nullifierIndexInPubSigArray) external;

    function setSigner(address signer) external;

    function removeVerifier(uint256 signatureAlgorithm) external;

    function removeSigner(address signer) external;

    function isRegistered(uint256 nullifier, address recipient) external view returns (bool);

    function getVerifier(uint256 signatureAlgorithm) external view returns (address);

    function getNullifierIndex(uint256 signatureAlgorithm) external view returns (uint256);

    function checkIfAddressIsSigner(address signer) external view returns (bool);
}
