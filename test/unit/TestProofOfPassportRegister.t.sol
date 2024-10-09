// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {Test, console} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ProofOfPassportRegister} from "../../src/ProofOfPassportRegister.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {DeployProofOfPassportRegister} from "../../script/DeployProofOfPassportRegister.s.sol";
import {CodeConstants} from "../../script/HelperConfig.s.sol";
import {IProofOfPassportRegister} from "../../src/interfaces/IProofOfPassportRegister.sol";
import {VerifierProveRSA65537SHA256} from "../../src/verifiers/prove/Verifier_prove_rsa_65537_sha256.sol";

contract TestProofOfPassportRegister is Test, Script, CodeConstants {
    ProofOfPassportRegister public proofOfPassportRegister;
    HelperConfig public helperConfig;

    uint256[] signatureAlgorithms;
    address[] verifiers;
    address[] signers;
    IProofOfPassportRegister.Proof private proof;

    uint256 public constant SECOND_SIGNATURE_ALGORITHM = 2;

    address SIGNER = makeAddr("signer");

    event RecipientRegistered(address indexed recipient, uint256 indexed nullifier);

    event VerifierSet(uint256 indexed signature_algorithm, address indexed verifier);

    event SignerSet(address indexed signer);

    event SignerRemoved(address indexed signer);

    event VerifierRemoved(uint256 indexed signature_algorithm);

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

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        uint256[45] memory pubSignals;

        proof = IProofOfPassportRegister.Proof({a: a, b: b, c: c, pubSignals: pubSignals});
        proof.pubSignals[SIGNATURE_ALGORITHM_INDEX_IN_PUB_SIGNALS] = SIGNATURE_ALGORITHM_RSA_65537_SHA256;
        
        vm.mockCall(
            verifiers[0],
            abi.encodeWithSelector(VerifierProveRSA65537SHA256(verifiers[0]).verifyProof.selector),
            abi.encode(true)
        );
    }

    /*//////////////////////////////////////////////////////////////
                             INITIAL VALUES
    //////////////////////////////////////////////////////////////*/
    function testInitialValues() public view {
        bool isSigner = proofOfPassportRegister.checkIfAddressIsSigner(SIGNER);
        address verifier = proofOfPassportRegister.getVerifier(SIGNATURE_ALGORITHM_RSA_65537_SHA256);
        uint256 nullifierIndex = proofOfPassportRegister.getNullifierIndex(SIGNATURE_ALGORITHM_RSA_65537_SHA256);
        uint256 signatureAlgorithmIndexInPubSignals = proofOfPassportRegister.SIGNATURE_ALGORITHM_INDEX_IN_PUB_SIGNALS();
        address owner = proofOfPassportRegister.owner();

        assertEq(isSigner, true);
        // change those to test against the deployed values
        assertNotEq(verifier, address(0));
        assertEq(nullifierIndex, NULLIFIER_INDEX_IN_PUB_SIGNAL);
        assertEq(signatureAlgorithmIndexInPubSignals, SIGNATURE_ALGORITHM_INDEX_IN_PUB_SIGNALS);

        if (block.chainid == LOCAL_CHAIN_ID) {
            assertEq(owner, DEFAULT_ANVIL_ADDRESS);
        }
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

    // /*//////////////////////////////////////////////////////////////
    //                             VERIFIER
    // //////////////////////////////////////////////////////////////*/
    function testOwnerShouldBeAbleToAddVerifierAndItShouldEmitAnEvent() public {
        address owner = proofOfPassportRegister.owner();

        VerifierProveRSA65537SHA256 mockVerifier = new VerifierProveRSA65537SHA256();

        vm.expectEmit(true, true, false, false, address(proofOfPassportRegister));
        emit VerifierSet(SECOND_SIGNATURE_ALGORITHM, address(mockVerifier));

        vm.prank(owner);
        proofOfPassportRegister.setVerifier(
            SECOND_SIGNATURE_ALGORITHM, address(mockVerifier), NULLIFIER_INDEX_IN_PUB_SIGNAL
        );

        address verifier = proofOfPassportRegister.getVerifier(SECOND_SIGNATURE_ALGORITHM);

        uint256 nullifierIndex = proofOfPassportRegister.getNullifierIndex(SECOND_SIGNATURE_ALGORITHM);

        assertEq(verifier, address(mockVerifier));
        assertEq(nullifierIndex, NULLIFIER_INDEX_IN_PUB_SIGNAL);
    }

    function testOwnerShouldNotBeAbleToAddVerifierWithAddress0() public {
        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);

        vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__ZeroAddress.selector);
        proofOfPassportRegister.setVerifier(SECOND_SIGNATURE_ALGORITHM, address(0), NULLIFIER_INDEX_IN_PUB_SIGNAL);
    }

    function testOwnerShouldNotBeAbleToAddWrongVerifierContract(address notAContract) public {
        // Skip test if 'notAContract' is actually a contract
        vm.assume(notAContract.code.length == 0);
        // Also, ensure it's not the zero address to avoid overlapping with other tests
        vm.assume(notAContract != address(0));

        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);

        vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__NotAContract.selector);
        proofOfPassportRegister.setVerifier(SECOND_SIGNATURE_ALGORITHM, notAContract, NULLIFIER_INDEX_IN_PUB_SIGNAL);
    }

    function testOwnerShouldNotBeAbleToAddInvalidVerifier() public {
        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);

        vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__InvalidVerifier.selector);
        proofOfPassportRegister.setVerifier(
            SECOND_SIGNATURE_ALGORITHM, address(proofOfPassportRegister), NULLIFIER_INDEX_IN_PUB_SIGNAL
        );
    }

    function testUserShouldNotBeAbleToAddVerifier(address user) public {
        address owner = proofOfPassportRegister.owner();
        // Exclude the owner from the fuzzed user addresses
        vm.assume(user != owner);

        VerifierProveRSA65537SHA256 mockVerifier = new VerifierProveRSA65537SHA256();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        proofOfPassportRegister.setVerifier(
            SECOND_SIGNATURE_ALGORITHM, address(mockVerifier), NULLIFIER_INDEX_IN_PUB_SIGNAL
        );
    }

    function testOwnerShouldBeAbleToRemoveVerifier() public {
        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);
        proofOfPassportRegister.removeVerifier(SIGNATURE_ALGORITHM_RSA_65537_SHA256);

        address verifier = proofOfPassportRegister.getVerifier(SIGNATURE_ALGORITHM_RSA_65537_SHA256);

        uint256 nullifierIndex = proofOfPassportRegister.getNullifierIndex(SIGNATURE_ALGORITHM_RSA_65537_SHA256);

        assertEq(verifier, address(0));
        assertEq(nullifierIndex, 0);
    }

    function testShouldEmitEventIfVerifierRemovedSuccesfully() public {
        address owner = proofOfPassportRegister.owner();

        vm.expectEmit(true, false, true, false, address(proofOfPassportRegister));
        emit VerifierRemoved(SIGNATURE_ALGORITHM_RSA_65537_SHA256);

        vm.prank(owner);
        proofOfPassportRegister.removeVerifier(SIGNATURE_ALGORITHM_RSA_65537_SHA256);
    }

    function testUserShouldNotBeAbleToRemoveVerifier(address user) public {
        address owner = proofOfPassportRegister.owner();
        // Exclude the owner from the fuzzed user addresses
        vm.assume(user != owner);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        proofOfPassportRegister.removeVerifier(SIGNATURE_ALGORITHM_RSA_65537_SHA256);
    }

    // /*//////////////////////////////////////////////////////////////
    //                          REGISTER WITH PROOF
    // //////////////////////////////////////////////////////////////*/
    function testSignerShouldBeAbleToRegisterProofAndEmitEventCorrectly() public {
        address RECIPIENT = makeAddr("recipient");

        vm.expectEmit(true, true, false, false, address(proofOfPassportRegister));
        emit RecipientRegistered(RECIPIENT, NULLIFIER);

        vm.prank(SIGNER);
        proofOfPassportRegister.registerWithProof(proof, RECIPIENT);

        bool isRegistered = proofOfPassportRegister.isRegistered(NULLIFIER, RECIPIENT);
        assertEq(isRegistered, true);
    }

    function testShouldRevertIfZeroAddressWhileRegistering() public {
        address RECIPIENT = address(0);

        vm.prank(SIGNER);
        vm.expectRevert(
            abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__ZeroAddress.selector)
        );
        proofOfPassportRegister.registerWithProof(proof, RECIPIENT);
    }

    function testUserShouldNotBeAbleToRegisterWithProof(address user) public {
        address RECIPIENT = makeAddr("recipient");
        // Exclude the signer from the fuzzed user addresses
        vm.assume(user != SIGNER);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__CallerNotSigner.selector)
        );
        proofOfPassportRegister.registerWithProof(proof, RECIPIENT);
    }

    function testShouldRevertIfRegisterTwice() public {
        address RECIPIENT = makeAddr("recipient");

        vm.prank(SIGNER);
        proofOfPassportRegister.registerWithProof(proof, RECIPIENT);

        vm.prank(SIGNER);
        vm.expectRevert(
            abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__ProofAlreadyRegistered.selector)
        );
        proofOfPassportRegister.registerWithProof(proof, RECIPIENT);
    }

    function testShouldRevertIfInvalidSignatureAlgorithmWhileRegistering(uint256 signatureAlgorithm) public {
        address RECIPIENT = makeAddr("recipient");
        proof.pubSignals[SIGNATURE_ALGORITHM_INDEX_IN_PUB_SIGNALS] = signatureAlgorithm;
        // Exclude the valid signature algorithm from the fuzzed inputs
        vm.assume(signatureAlgorithm != SIGNATURE_ALGORITHM_RSA_65537_SHA256);

        vm.prank(SIGNER);
        vm.expectRevert(
            abi.encodeWithSelector(
                IProofOfPassportRegister.ProofOfPassportRegister__UnsupportedSignatureAlgorithm.selector
            )
        );
        proofOfPassportRegister.registerWithProof(proof, RECIPIENT);
    }

    function testShouldRevertIfInvalidProofWhileRegistering() public {
        address RECIPIENT = makeAddr("recipient");

        vm.mockCall(
            verifiers[0],
            abi.encodeWithSelector(VerifierProveRSA65537SHA256(verifiers[0]).verifyProof.selector),
            abi.encode(false)
        );

        vm.prank(SIGNER);
        vm.expectRevert(abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__InvalidProof.selector));
        proofOfPassportRegister.registerWithProof(proof, RECIPIENT);
    }

    // /*//////////////////////////////////////////////////////////////
    //                          VALIDATE PROOF
    // //////////////////////////////////////////////////////////////*/
    function testShouldValidateProofAndEmitEvent() public {
        address RECIPIENT = makeAddr("recipient");

        vm.prank(SIGNER);
        proofOfPassportRegister.registerWithProof(proof, RECIPIENT);

        bool isValid = proofOfPassportRegister.validateProof(proof, RECIPIENT);

        assertEq(isValid, true);
    }

    function testShouldRevertIfZeroAddressWhileValidating() public {
        address RECIPIENT = address(0);

        vm.expectRevert(
            abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__ZeroAddress.selector)
        );
        proofOfPassportRegister.validateProof(proof, RECIPIENT);
    }

    function testShouldRevertIfNotRegisteredWhileValidating() public {
        address RECIPIENT = makeAddr("recipient");

        vm.expectRevert(
            abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__NullifierDoesNotExist.selector)
        );
        proofOfPassportRegister.validateProof(proof, RECIPIENT);
    }

    function testShouldRevertIfInvalidProofWhileValidating() public {
        address RECIPIENT = makeAddr("recipient");

        vm.prank(SIGNER);
        proofOfPassportRegister.registerWithProof(proof, RECIPIENT);

        vm.mockCall(
            verifiers[0],
            abi.encodeWithSelector(VerifierProveRSA65537SHA256(verifiers[0]).verifyProof.selector),
            abi.encode(false)
        );

        vm.expectRevert(abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__InvalidProof.selector));
        proofOfPassportRegister.validateProof(proof, RECIPIENT);
    }
}
