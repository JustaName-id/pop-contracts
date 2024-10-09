// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {Test, console} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ProofOfPassportRegister} from "../../src/ProofOfPassportRegister.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {DeployProofOfPassportRegister} from "../../script/DeployProofOfPassportRegister.s.sol";
import {CodeConstants} from "../../script/HelperConfig.s.sol";
import {VerifierProveRSA65537SHA1} from "../../src/verifiers/prove/Verifier_prove_rsa_65537_sha1.sol";
import {VerifierProveRSAPSS65537SHA256} from "../../src/verifiers/prove/Verifier_prove_rsapss_65537_sha256.sol";

contract TestRegisterFlow is Test, Script, CodeConstants {
    ProofOfPassportRegister public proofOfPassportRegister;
    HelperConfig public helperConfig;

    VerifierProveRSA65537SHA1 public verifierProveRSA65537SHA1;
    VerifierProveRSAPSS65537SHA256 public verifierProveRSAPSS65537SHA256;

    address SIGNER = makeAddr("signer");

    address OWNER;

    uint256[] signatureAlgorithms;
    address[] verifiers;
    address[] signers;

    event SignerSet(address indexed signer);

    event RecipientRegistered(address indexed recipient, uint256 indexed nullifier);

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        DeployProofOfPassportRegister deployer = new DeployProofOfPassportRegister();
        (proofOfPassportRegister, helperConfig) = deployer.run();
        HelperConfig.NetworkConfig memory config = helperConfig.getConfig();

        signatureAlgorithms = config.signatureAlgorithms;
        verifiers = config.verifiers;
        signers = config.signers;

        OWNER = proofOfPassportRegister.owner();

        // Add missing verifiers
        verifierProveRSA65537SHA1 = new VerifierProveRSA65537SHA1();
        verifierProveRSAPSS65537SHA256 = new VerifierProveRSAPSS65537SHA256();

        vm.prank(OWNER);
        proofOfPassportRegister.setVerifier(
            SIGNATURE_ALGORITHM_RSA_65537_SHA1, address(verifierProveRSA65537SHA1), NULLIFIER_INDEX_IN_PUB_SIGNAL
        );
        vm.prank(OWNER);
        proofOfPassportRegister.setVerifier(
            SIGNATURE_ALGORITHM_RSA_PSS_65537_SHA256,
            address(verifierProveRSAPSS65537SHA256),
            NULLIFIER_INDEX_IN_PUB_SIGNAL
        );
    }

    function testRegisterFlowSha256RSA65537(address recipient, address signer, address user) public {
        vm.assume(recipient != address(0));
        vm.assume(user != OWNER);
        vm.assume(signer != user);

        address newSigner = makeAddr("newSigner");
        uint256 nullifier = SHA256_RSA_65537_PROOF.pubSignals[proofOfPassportRegister.getNullifierIndex(
            SIGNATURE_ALGORITHM_RSA_65537_SHA256
        )];

        vm.expectEmit(true, false, false, false, address(proofOfPassportRegister));
        emit SignerSet(newSigner);

        vm.prank(OWNER);
        proofOfPassportRegister.setSigner(newSigner);

        bool isNewSigner = proofOfPassportRegister.checkIfAddressIsSigner(newSigner);
        assertTrue(isNewSigner);

        vm.expectEmit(true, true, false, false, address(proofOfPassportRegister));
        emit RecipientRegistered(recipient, nullifier);

        vm.prank(newSigner);
        proofOfPassportRegister.registerWithProof(SHA256_RSA_65537_PROOF, recipient);

        vm.prank(user);
        bool isValid = proofOfPassportRegister.validateProof(SHA256_RSA_65537_PROOF, recipient);
        assertTrue(isValid);
    }

    function testRegisterFlowSha1RSA65537(address recipient, address signer, address user) public {
        vm.assume(recipient != address(0));
        vm.assume(user != OWNER);
        vm.assume(signer != user);

        address newSigner = makeAddr("newSigner");
        uint256 nullifier = SHA1_RSA_65537_PROOF.pubSignals[proofOfPassportRegister.getNullifierIndex(
            SIGNATURE_ALGORITHM_RSA_65537_SHA1
        )];

        vm.expectEmit(true, false, false, false, address(proofOfPassportRegister));
        emit SignerSet(newSigner);

        vm.prank(OWNER);
        proofOfPassportRegister.setSigner(newSigner);

        bool isNewSigner = proofOfPassportRegister.checkIfAddressIsSigner(newSigner);
        assertTrue(isNewSigner);

        vm.expectEmit(true, true, false, false, address(proofOfPassportRegister));
        emit RecipientRegistered(recipient, nullifier);

        vm.prank(newSigner);
        proofOfPassportRegister.registerWithProof(SHA1_RSA_65537_PROOF, recipient);

        vm.prank(user);
        bool isValid = proofOfPassportRegister.validateProof(SHA1_RSA_65537_PROOF, recipient);
        assertTrue(isValid);
    }

    function testRegisterFlowSha256RSAPSS65537(address recipient, address signer, address user) public {
        vm.assume(recipient != address(0));
        vm.assume(user != OWNER);
        vm.assume(signer != user);

        address newSigner = makeAddr("newSigner");
        uint256 nullifier = SHA256_RSA_PSS_65537_PROOF.pubSignals[proofOfPassportRegister.getNullifierIndex(
            SIGNATURE_ALGORITHM_RSA_PSS_65537_SHA256
        )];

        vm.expectEmit(true, false, false, false, address(proofOfPassportRegister));
        emit SignerSet(newSigner);

        vm.prank(OWNER);
        proofOfPassportRegister.setSigner(newSigner);

        bool isNewSigner = proofOfPassportRegister.checkIfAddressIsSigner(newSigner);
        assertTrue(isNewSigner);

        vm.expectEmit(true, true, false, false, address(proofOfPassportRegister));
        emit RecipientRegistered(recipient, nullifier);

        vm.prank(newSigner);
        proofOfPassportRegister.registerWithProof(SHA256_RSA_PSS_65537_PROOF, recipient);

        vm.prank(user);
        bool isValid = proofOfPassportRegister.validateProof(SHA256_RSA_PSS_65537_PROOF, recipient);
        assertTrue(isValid);
    }
}
