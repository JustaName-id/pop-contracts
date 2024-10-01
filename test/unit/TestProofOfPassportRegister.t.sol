// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {Script} from "forge-std/Script.sol";
import {ProofOfPassportRegister} from "../../src/ProofOfPassportRegister.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {DeployProofOfPassportRegister} from "../../script/DeployProofOfPassportRegister.s.sol";
import {CodeConstants} from "../../script/HelperConfig.s.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IProofOfPassportRegister} from "../../src/interfaces/IProofOfPassportRegister.sol";
import {Verifier_register_sha256WithRSASSAPSS_65537} from
    "../../src/verifiers/register/Verifier_register_sha256WithRSASSAPSS_65537.sol";
import {Verifier_dsc_sha256_rsa_4096} from "../../src/verifiers/dsc/Verifier_dsc_sha256_rsa_4096.sol";
import {MerkleTreeRegistry} from "../../src/MerkleTreeRegistry.sol";

contract TestProofOfPassportRegister is Test, Script, CodeConstants {
    ProofOfPassportRegister public proofOfPassportRegister;
    HelperConfig public helperConfig;

    uint256 attestationId;
    uint256 merkleRoot;
    uint256[] signatureAlgorithms;
    address[] verifiers;
    uint256[] cscaSignatureAlgorithms;
    address[] cscaVerifiers;
    address[] signers;
    IProofOfPassportRegister.Proof public proof;
    IProofOfPassportRegister.CSCAProof public cscaProof;

    uint256 public constant SECOND_SIGNATURE_ALGORITHM = 2;
    uint256 public constant SECOND_CSCA_SIGNATURE_ALGORITHM = 2;

    uint256 public constant NEW_MERKLE_ROOT =
        97617982452311505471274934026898123532183481230970869414506856451449510095384;

    address SIGNER = makeAddr("signer");

    event RecipientRegistered(address indexed recipient, uint256 indexed nullifier);

    event VerifierSet(uint256 indexed signature_algorithm, address indexed verifier);

    event CSCAVerifierSet(uint256 indexed signature_algorithm, address indexed verifier);

    event SignerSet(address indexed signer);

    event SignerRemoved(address indexed signer);

    event VerifierRemoved(uint256 indexed signature_algorithm);

    event CSCAVerifierRemoved(uint256 indexed signature_algorithm);

    event RootUpdated(uint256 indexed newRoot);

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        DeployProofOfPassportRegister deployer = new DeployProofOfPassportRegister();
        (proofOfPassportRegister, helperConfig) = deployer.run();
        HelperConfig.NetworkConfig memory config = helperConfig.getConfig();

        attestationId = config.attestationId;
        merkleRoot = config.merkleRoot;
        signatureAlgorithms = config.signatureAlgorithms;
        verifiers = config.verifiers;
        cscaSignatureAlgorithms = config.cscaSignatureAlgorithms;
        cscaVerifiers = config.cscaVerifiers;
        signers = config.signers;

        proof = IProofOfPassportRegister.Proof({
            a: [uint256(0), uint256(0)],
            b: [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            c: [uint256(0), uint256(0)],
            blinded_dsc_commitment: uint256(0),
            nullifier: NULLIFIER,
            commitment: uint256(0),
            attestation_id: ATTESTATION_ID
        });

        cscaProof = IProofOfPassportRegister.CSCAProof({
            a: [uint256(0), uint256(0)],
            b: [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            c: [uint256(0), uint256(0)],
            blinded_dsc_commitment: uint256(0),
            merkle_root: MERKLE_ROOT
        });

        vm.mockCall(
            verifiers[0],
            abi.encodeWithSelector(Verifier_register_sha256WithRSASSAPSS_65537(verifiers[0]).verifyProof.selector),
            abi.encode(true)
        );

        vm.mockCall(
            cscaVerifiers[0],
            abi.encodeWithSelector(Verifier_dsc_sha256_rsa_4096(cscaVerifiers[0]).verifyProof.selector),
            abi.encode(true)
        );
    }

    /*//////////////////////////////////////////////////////////////
                             INITIAL VALUES
    //////////////////////////////////////////////////////////////*/
    function testInitialValues() public view {
        uint256 actualAttestationId = proofOfPassportRegister.getAttestationId();
        bool isSigner = proofOfPassportRegister.checkIfAddressIsSigner(SIGNER);
        address verifier = proofOfPassportRegister.getVerifier(SIGNATURE_ALGORITHM);
        address cscaVerifier = proofOfPassportRegister.getCSCAVerifier(CSCA_SIGNATURE_ALGORITHM);
        uint256 root = proofOfPassportRegister.getRoot();
        address owner = proofOfPassportRegister.owner();

        assertEq(actualAttestationId, attestationId);
        assertEq(isSigner, true);
        assertEq(root, MERKLE_ROOT);
        if (block.chainid == LOCAL_CHAIN_ID) {
            assertEq(owner, DEFAULT_ANVIL_ADDRESS);
        }
        // change those to test against the deployed values
        assertNotEq(verifier, address(0));
        assertNotEq(cscaVerifier, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                                 SIGNER
    //////////////////////////////////////////////////////////////*/
    function testAddingNewSignerAsOwner() public {
        address SIGNER2 = makeAddr("signer2");

        address owner = proofOfPassportRegister.owner();

        vm.expectEmit(true, false, false, false, address(proofOfPassportRegister));
        emit SignerSet(SIGNER2);

        vm.prank(owner);
        proofOfPassportRegister.setSigner(SIGNER2);

        bool isSigner = proofOfPassportRegister.checkIfAddressIsSigner(SIGNER2);

        assertEq(isSigner, true);
    }

    function testAddingNewSignerAsUserWillFail(address user) public {
        address SIGNER2 = makeAddr("signer2");

        address owner = proofOfPassportRegister.owner();
        // Exclude the signer from the fuzzed user addresses
        vm.assume(user != owner);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        proofOfPassportRegister.setSigner(SIGNER2);
    }

    function testAddingAddress0AsSignerWillFail() public {
        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);

        vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__ZeroAddress.selector);
        proofOfPassportRegister.setSigner(address(0));
    }

    function testOwnerShouldBeAbleToRemoveSignerAndShouldEmitAnEvent() public {
        address owner = proofOfPassportRegister.owner();

        vm.expectEmit(true, false, false, false, address(proofOfPassportRegister));
        emit SignerRemoved(SIGNER);

        vm.prank(owner);
        proofOfPassportRegister.removeSigner(SIGNER);

        bool isSigner = proofOfPassportRegister.checkIfAddressIsSigner(SIGNER);

        assertEq(isSigner, false);
    }

    function testUserShouldNotBeAbleToRemoveSigner(address user) public {
        address owner = proofOfPassportRegister.owner();
        // Exclude the owner from the fuzzed user addresses
        vm.assume(user != owner);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        proofOfPassportRegister.removeSigner(SIGNER);
    }

    /*//////////////////////////////////////////////////////////////
                                VERIFIER
    //////////////////////////////////////////////////////////////*/
    function testOwnerShouldBeAbleToAddVerifierAndItShouldEmitAnEvent() public {
        address owner = proofOfPassportRegister.owner();

        Verifier_register_sha256WithRSASSAPSS_65537 mockVerifier = new Verifier_register_sha256WithRSASSAPSS_65537();

        vm.expectEmit(true, true, false, false, address(proofOfPassportRegister));
        emit VerifierSet(SECOND_SIGNATURE_ALGORITHM, address(mockVerifier));

        vm.prank(owner);
        proofOfPassportRegister.setVerifier(SECOND_SIGNATURE_ALGORITHM, address(mockVerifier));

        address verifier = proofOfPassportRegister.getVerifier(SECOND_SIGNATURE_ALGORITHM);

        assertEq(verifier, address(mockVerifier));
    }

    function testOwnerShouldNotBeAbleToAddVerifierWithAddress0() public {
        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);

        vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__ZeroAddress.selector);
        proofOfPassportRegister.setVerifier(SECOND_SIGNATURE_ALGORITHM, address(0));
    }

    function testOwnerShouldNotBeAbleToAddWrongVerifierContract(address notAContract) public {
        // Skip test if 'notAContract' is actually a contract
        vm.assume(notAContract.code.length == 0);
        // Also, ensure it's not the zero address to avoid overlapping with other tests
        vm.assume(notAContract != address(0));

        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);

        vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__NotAContract.selector);
        proofOfPassportRegister.setVerifier(SECOND_SIGNATURE_ALGORITHM, notAContract);
    }

    function testOwnerShouldNotBeAbleToAddVerifierWithInvalidVerifier() public {
        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);

        vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__InvalidVerifier.selector);
        proofOfPassportRegister.setVerifier(SECOND_SIGNATURE_ALGORITHM, address(proofOfPassportRegister));
    }

    function testUserShouldNotBeAbleToAddVerifier(address user) public {
        address owner = proofOfPassportRegister.owner();
        // Exclude the owner from the fuzzed user addresses
        vm.assume(user != owner);

        Verifier_register_sha256WithRSASSAPSS_65537 mockVerifier = new Verifier_register_sha256WithRSASSAPSS_65537();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        proofOfPassportRegister.setVerifier(SECOND_SIGNATURE_ALGORITHM, address(mockVerifier));
    }

    function testOwnerShouldBeAbleToRemoveVerifier() public {
        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);
        proofOfPassportRegister.removeVerifier(SIGNATURE_ALGORITHM);

        address verifier = proofOfPassportRegister.getVerifier(SIGNATURE_ALGORITHM);

        assertEq(verifier, address(0));
    }

    function testShouldEmitEventIfVerifierRemovedSuccesfully() public {
        address owner = proofOfPassportRegister.owner();

        vm.expectEmit(true, false, true, false, address(proofOfPassportRegister));
        emit VerifierRemoved(SIGNATURE_ALGORITHM);

        vm.prank(owner);
        proofOfPassportRegister.removeVerifier(SIGNATURE_ALGORITHM);
    }

    function testUserShouldNotBeAbleToRemoveVerifier(address user) public {
        address owner = proofOfPassportRegister.owner();
        // Exclude the owner from the fuzzed user addresses
        vm.assume(user != owner);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        proofOfPassportRegister.removeVerifier(SIGNATURE_ALGORITHM);
    }

    /*//////////////////////////////////////////////////////////////
                              VERIFIER CSCA
    //////////////////////////////////////////////////////////////*/

    function testOwnerShouldBeAbleToAddCscaVerifierAndItShouldEmitAnEvent() public {
        address owner = proofOfPassportRegister.owner();

        Verifier_dsc_sha256_rsa_4096 mockCscaVerifier = new Verifier_dsc_sha256_rsa_4096();

        vm.expectEmit(true, true, false, false, address(proofOfPassportRegister));

        emit CSCAVerifierSet(SECOND_CSCA_SIGNATURE_ALGORITHM, address(mockCscaVerifier));

        vm.prank(owner);
        proofOfPassportRegister.setCSCAVerifier(SECOND_CSCA_SIGNATURE_ALGORITHM, address(mockCscaVerifier));

        address cscaVerifier = proofOfPassportRegister.getCSCAVerifier(SECOND_CSCA_SIGNATURE_ALGORITHM);

        assertEq(cscaVerifier, address(mockCscaVerifier));
    }

    function testOwnerShouldNotBeAbleToAddCscaVerifierWithAddress0() public {
        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);

        vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__ZeroAddress.selector);
        proofOfPassportRegister.setCSCAVerifier(SECOND_CSCA_SIGNATURE_ALGORITHM, address(0));
    }

    function testOwnerShouldNotBeAbleToAddWrongCscaVerifierContract(address notAContract) public {
        // Skip test if 'notAContract' is actually a contract
        vm.assume(notAContract.code.length == 0);
        // Also, ensure it's not the zero address to avoid overlapping with other tests
        vm.assume(notAContract != address(0));

        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);

        vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__NotAContract.selector);
        proofOfPassportRegister.setCSCAVerifier(SECOND_CSCA_SIGNATURE_ALGORITHM, notAContract);
    }

    function testOwnerShouldNotBeAbleToAddCscaVerifierWithInvalidVerifier() public {
        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);

        vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__InvalidCSCAVerifier.selector);
        proofOfPassportRegister.setCSCAVerifier(SECOND_CSCA_SIGNATURE_ALGORITHM, address(proofOfPassportRegister));
    }

    function testUserShouldNotBeAbleToAddCscaVerifier(address user) public {
        address owner = proofOfPassportRegister.owner();
        // Exclude the owner from the fuzzed user addresses
        vm.assume(user != owner);

        Verifier_dsc_sha256_rsa_4096 mockCscaVerifier = new Verifier_dsc_sha256_rsa_4096();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        proofOfPassportRegister.setCSCAVerifier(SECOND_CSCA_SIGNATURE_ALGORITHM, address(mockCscaVerifier));
    }

    function testOwnerShouldBeAbleToRemoveVerifierAndItShouldEmitEvent() public {
        address owner = proofOfPassportRegister.owner();

        vm.expectEmit(true, false, true, false, address(proofOfPassportRegister));
        emit CSCAVerifierRemoved(CSCA_SIGNATURE_ALGORITHM);

        vm.prank(owner);
        proofOfPassportRegister.removeCSCAVerifier(CSCA_SIGNATURE_ALGORITHM);

        address cscaVerifier = proofOfPassportRegister.getCSCAVerifier(CSCA_SIGNATURE_ALGORITHM);

        assertEq(cscaVerifier, address(0));
    }

    function testUserShouldNotBeAbleToRemoveCscaVerifier(address user) public {
        address owner = proofOfPassportRegister.owner();
        // Exclude the owner from the fuzzed user addresses
        vm.assume(user != owner);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        proofOfPassportRegister.removeCSCAVerifier(CSCA_SIGNATURE_ALGORITHM);
    }

    /*//////////////////////////////////////////////////////////////
                             REGISTER WITH PROOF
    //////////////////////////////////////////////////////////////*/
    function testSignerShouldBeAbleToRegisterProofAndEmitEventCorrectly() public {
        address RECIPIENT = makeAddr("recipient");

        vm.expectEmit(true, true, false, false, address(proofOfPassportRegister));
        emit RecipientRegistered(RECIPIENT, NULLIFIER);

        vm.prank(SIGNER);
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );

        bool isRegistered = proofOfPassportRegister.isRegistered(NULLIFIER, RECIPIENT);
        assertEq(isRegistered, true);
    }

    function testUserShouldNotBeAbleToRegisterWithProof(address user) public {
        address RECIPIENT = makeAddr("recipient");
        // Exclude the signer from the fuzzed user addresses
        vm.assume(user != SIGNER);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__CallerNotSigner.selector)
        );
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );
    }

    function testShouldRevertIfRegisterTwice() public {
        address RECIPIENT = makeAddr("recipient");

        vm.prank(SIGNER);
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );

        vm.prank(SIGNER);
        vm.expectRevert(
            abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__ProofAlreadyRegistered.selector)
        );
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );
    }

    function testShouldRevertIfInvalidSignatureAlgorithmWhileRegistering(uint256 signatureAlgorithm) public {
        address RECIPIENT = makeAddr("recipient");
        // Exclude the valid signature algorithm from the fuzzed inputs
        vm.assume(signatureAlgorithm != SIGNATURE_ALGORITHM);

        vm.prank(SIGNER);
        vm.expectRevert(
            abi.encodeWithSelector(
                IProofOfPassportRegister.ProofOfPassportRegister__UnsupportedSignatureAlgorithm.selector
            )
        );
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, signatureAlgorithm, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );
    }

    function testShouldRevertIfInvalidCscaSignatureAlgorithmWhileRegistering(uint256 cscaSignatureAlgorithm) public {
        address RECIPIENT = makeAddr("recipient");
        // Exclude the valid signature algorithm from the fuzzed inputs
        vm.assume(cscaSignatureAlgorithm != SIGNATURE_ALGORITHM);

        vm.prank(SIGNER);
        vm.expectRevert(
            abi.encodeWithSelector(
                IProofOfPassportRegister.ProofOfPassportRegister_UnsupportedSignatureAlgorithmCSCA.selector
            )
        );
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, cscaSignatureAlgorithm, RECIPIENT
        );
    }

    function testShouldRevertIfInvalidAttestationIdWhileRegistering(uint256 newAttestationId) public {
        address RECIPIENT = makeAddr("recipient");

        vm.assume(newAttestationId != ATTESTATION_ID);
        proof.attestation_id = newAttestationId;

        vm.prank(SIGNER);
        vm.expectRevert(
            abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__InvalidAttestationId.selector)
        );
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );
    }

    function testShouldRevertIfBlindedDscCommitmentDontMatchWhileRegistering(uint256 newBlindedDscCommitment) public {
        address RECIPIENT = makeAddr("recipient");

        vm.assume(newBlindedDscCommitment != uint256(0));
        proof.blinded_dsc_commitment = newBlindedDscCommitment;

        vm.prank(SIGNER);
        vm.expectRevert(
            abi.encodeWithSelector(
                IProofOfPassportRegister.ProofOfPassportRegister__BlindedDSCCommitmentDontMatch.selector
            )
        );
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );
    }

    function testShouldRevertIfInvalidMerkleRootWhileRegistering(uint256 newMerkleRoot) public {
        address RECIPIENT = makeAddr("recipient");

        vm.assume(newMerkleRoot != MERKLE_ROOT);
        cscaProof.merkle_root = newMerkleRoot;

        vm.prank(SIGNER);
        vm.expectRevert(
            abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__InvalidMerkleRoot.selector)
        );
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );
    }

    function testShouldRevertIfInvalidProofWhileRegistering() public {
        address RECIPIENT = makeAddr("recipient");

        vm.mockCall(
            verifiers[0],
            abi.encodeWithSelector(Verifier_register_sha256WithRSASSAPSS_65537(verifiers[0]).verifyProof.selector),
            abi.encode(false)
        );

        vm.prank(SIGNER);
        vm.expectRevert(abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__InvalidProof.selector));
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );
    }

    function testShouldRevertIfInvalidCscaProofWhileRegistering() public {
        address RECIPIENT = makeAddr("recipient");

        vm.mockCall(
            cscaVerifiers[0],
            abi.encodeWithSelector(Verifier_dsc_sha256_rsa_4096(cscaVerifiers[0]).verifyProof.selector),
            abi.encode(false)
        );

        vm.prank(SIGNER);
        vm.expectRevert(
            abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__InvalidCSCAProof.selector)
        );
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );
    }

    /*//////////////////////////////////////////////////////////////
                             VALIDATE PROOF
    //////////////////////////////////////////////////////////////*/
    function testShouldValidateProofAndEmitEvent() public {
        address RECIPIENT = makeAddr("recipient");

        vm.prank(SIGNER);
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );

        bool isValid = proofOfPassportRegister.validateProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );

        assertEq(isValid, true);
    }

    function testShouldRevertIfNotRegisteredWhileValidating() public {
        address RECIPIENT = makeAddr("recipient");

        vm.expectRevert(
            abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__NullifierDoesNotExist.selector)
        );
        proofOfPassportRegister.validateProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );
    }

    function testShouldRevertIfInvalidSignatureAlgorithmWhileValidating(uint256 newSignatureAlgorithm) public {
        address RECIPIENT = makeAddr("recipient");
        vm.assume(newSignatureAlgorithm != SIGNATURE_ALGORITHM);

        vm.prank(SIGNER);
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                IProofOfPassportRegister.ProofOfPassportRegister__UnsupportedSignatureAlgorithm.selector
            )
        );
        proofOfPassportRegister.validateProof(
            proof, cscaProof, newSignatureAlgorithm, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );
    }

    function testShouldRevertIfInvalidCscaSignatureAlgorithmWhileValidating(uint256 newCscaSignatureAlgorithm) public {
        address RECIPIENT = makeAddr("recipient");
        vm.assume(newCscaSignatureAlgorithm != CSCA_SIGNATURE_ALGORITHM);

        vm.prank(SIGNER);
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                IProofOfPassportRegister.ProofOfPassportRegister_UnsupportedSignatureAlgorithmCSCA.selector
            )
        );
        proofOfPassportRegister.validateProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, newCscaSignatureAlgorithm, RECIPIENT
        );
    }

    function testShouldRevertIfInvalidAttestationIdWhileValidating(uint256 newAttestationId) public {
        address RECIPIENT = makeAddr("recipient");
        vm.assume(newAttestationId != ATTESTATION_ID);

        vm.prank(SIGNER);
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );

        proof.attestation_id = newAttestationId;

        vm.expectRevert(
            abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__InvalidAttestationId.selector)
        );
        proofOfPassportRegister.validateProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );
    }

    function testShouldRevertIfBlindedDscCommitmentDontMatchWhileValidating(uint256 newBlindedDscCommitment) public {
        address RECIPIENT = makeAddr("recipient");
        vm.assume(newBlindedDscCommitment != uint256(0));

        vm.prank(SIGNER);
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );

        proof.blinded_dsc_commitment = newBlindedDscCommitment;

        vm.expectRevert(
            abi.encodeWithSelector(
                IProofOfPassportRegister.ProofOfPassportRegister__BlindedDSCCommitmentDontMatch.selector
            )
        );
        proofOfPassportRegister.validateProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );
    }

    function testShouldRevertIfInvalidMerkleRootWhileValidating(uint256 newMerkleRoot) public {
        address RECIPIENT = makeAddr("recipient");
        vm.assume(newMerkleRoot != MERKLE_ROOT);

        vm.prank(SIGNER);
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );

        cscaProof.merkle_root = newMerkleRoot;

        vm.expectRevert(
            abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__InvalidMerkleRoot.selector)
        );
        proofOfPassportRegister.validateProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );
    }

    function testShouldRevertIfInvalidProofWhileValidating() public {
        address RECIPIENT = makeAddr("recipient");

        vm.prank(SIGNER);
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );

        vm.mockCall(
            verifiers[0],
            abi.encodeWithSelector(Verifier_register_sha256WithRSASSAPSS_65537(verifiers[0]).verifyProof.selector),
            abi.encode(false)
        );

        vm.expectRevert(abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__InvalidProof.selector));
        proofOfPassportRegister.validateProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );
    }

    function testShouldRevertIfInvalidCscaProofWhileValidating() public {
        address RECIPIENT = makeAddr("recipient");

        vm.prank(SIGNER);
        proofOfPassportRegister.registerWithProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );

        vm.mockCall(
            cscaVerifiers[0],
            abi.encodeWithSelector(Verifier_dsc_sha256_rsa_4096(cscaVerifiers[0]).verifyProof.selector),
            abi.encode(false)
        );

        vm.expectRevert(
            abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__InvalidCSCAProof.selector)
        );
        proofOfPassportRegister.validateProof(
            proof, cscaProof, SIGNATURE_ALGORITHM, CSCA_SIGNATURE_ALGORITHM, RECIPIENT
        );
    }

    /*//////////////////////////////////////////////////////////////
                           MERKLE TREE REGISTRY
    //////////////////////////////////////////////////////////////*/
    function testMerkleTreeRegistryShouldReturnTheRoot() public view {
        uint256 root = proofOfPassportRegister.getRoot();

        assertEq(root, MERKLE_ROOT);
    }

    function testOwnerShouldBeAbleToSetNewRootAndItEmitsAnEvent() public {
        address owner = proofOfPassportRegister.owner();

        vm.expectEmit(true, false, false, false, address(proofOfPassportRegister));
        emit RootUpdated(NEW_MERKLE_ROOT);

        vm.prank(owner);
        proofOfPassportRegister.setRoot(NEW_MERKLE_ROOT);

        bool newRootSet = proofOfPassportRegister.checkRoot(NEW_MERKLE_ROOT);

        assert(newRootSet == true);
    }

    function testShouldRevertIfSameRootIsSet() public {
        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);

        vm.expectRevert(MerkleTreeRegistry.MerkleTreeRegistry__SameRoot.selector);
        proofOfPassportRegister.setRoot(MERKLE_ROOT);
    }

    function testUserShouldNotBeAbleToSetNewRoot(address user) public {
        address owner = proofOfPassportRegister.owner();
        // Exclude the owner from the fuzzed user addresses
        vm.assume(user != owner);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        proofOfPassportRegister.setRoot(NEW_MERKLE_ROOT);
    }
}
