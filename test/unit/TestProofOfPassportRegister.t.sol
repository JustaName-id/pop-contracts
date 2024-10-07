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
// import {Verifier_register_sha256WithRSASSAPSS_65537} from
//     "../../src/verifiers/register/Verifier_register_sha256WithRSASSAPSS_65537.sol";

// contract TestProofOfPassportRegister is Test, Script, CodeConstants {
//     ProofOfPassportRegister public proofOfPassportRegister;
//     HelperConfig public helperConfig;

//     uint256 attestationId;
//     uint256[] signatureAlgorithms;
//     address[] verifiers;
//     address[] signers;
//     IProofOfPassportRegister.Proof public proof;

//     uint256 public constant SECOND_SIGNATURE_ALGORITHM = 2;

//     address SIGNER = makeAddr("signer");

//     event RecipientRegistered(address indexed recipient, uint256 indexed nullifier);

//     event VerifierSet(uint256 indexed signature_algorithm, address indexed verifier);

//     event SignerSet(address indexed signer);

//     event SignerRemoved(address indexed signer);

//     event VerifierRemoved(uint256 indexed signature_algorithm);

//     /*//////////////////////////////////////////////////////////////
//                                  SETUP
//     //////////////////////////////////////////////////////////////*/
//     function setUp() public {
//         DeployProofOfPassportRegister deployer = new DeployProofOfPassportRegister();
//         (proofOfPassportRegister, helperConfig) = deployer.run();
//         HelperConfig.NetworkConfig memory config = helperConfig.getConfig();

//         attestationId = config.attestationId;
//         signatureAlgorithms = config.signatureAlgorithms;
//         verifiers = config.verifiers;
//         signers = config.signers;

//         proof = IProofOfPassportRegister.Proof({
//             a: [uint256(0), uint256(0)],
//             b: [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
//             c: [uint256(0), uint256(0)],
//             blinded_dsc_commitment: uint256(0),
//             nullifier: NULLIFIER,
//             commitment: uint256(0),
//             attestation_id: ATTESTATION_ID
//         });

//         vm.mockCall(
//             verifiers[0],
//             abi.encodeWithSelector(Verifier_register_sha256WithRSASSAPSS_65537(verifiers[0]).verifyProof.selector),
//             abi.encode(true)
//         );
//     }

//     /*//////////////////////////////////////////////////////////////
//                              INITIAL VALUES
//     //////////////////////////////////////////////////////////////*/
//     function testInitialValues() public view {
//         uint256 actualAttestationId = proofOfPassportRegister.getAttestationId();
//         bool isSigner = proofOfPassportRegister.checkIfAddressIsSigner(SIGNER);
//         address verifier = proofOfPassportRegister.getVerifier(SIGNATURE_ALGORITHM);
//         address owner = proofOfPassportRegister.owner();

//         assertEq(actualAttestationId, attestationId);
//         assertEq(isSigner, true);
//         if (block.chainid == LOCAL_CHAIN_ID) {
//             assertEq(owner, DEFAULT_ANVIL_ADDRESS);
//         }
//         // change those to test against the deployed values
//         assertNotEq(verifier, address(0));
//     }

//     /*//////////////////////////////////////////////////////////////
//                                  SIGNER
//     //////////////////////////////////////////////////////////////*/
//     function testAddingNewSignerAsOwner() public {
//         address SIGNER2 = makeAddr("signer2");

//         address owner = proofOfPassportRegister.owner();

//         vm.expectEmit(true, false, false, false, address(proofOfPassportRegister));
//         emit SignerSet(SIGNER2);

//         vm.prank(owner);
//         proofOfPassportRegister.setSigner(SIGNER2);

//         bool isSigner = proofOfPassportRegister.checkIfAddressIsSigner(SIGNER2);

//         assertEq(isSigner, true);
//     }

//     function testAddingNewSignerAsUserWillFail(address user) public {
//         address SIGNER2 = makeAddr("signer2");

//         address owner = proofOfPassportRegister.owner();
//         // Exclude the signer from the fuzzed user addresses
//         vm.assume(user != owner);

//         vm.prank(user);
//         vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
//         proofOfPassportRegister.setSigner(SIGNER2);
//     }

//     function testAddingAddress0AsSignerWillFail() public {
//         address owner = proofOfPassportRegister.owner();

//         vm.prank(owner);

//         vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__ZeroAddress.selector);
//         proofOfPassportRegister.setSigner(address(0));
//     }

//     function testOwnerShouldBeAbleToRemoveSignerAndShouldEmitAnEvent() public {
//         address owner = proofOfPassportRegister.owner();

//         vm.expectEmit(true, false, false, false, address(proofOfPassportRegister));
//         emit SignerRemoved(SIGNER);

//         vm.prank(owner);
//         proofOfPassportRegister.removeSigner(SIGNER);

//         bool isSigner = proofOfPassportRegister.checkIfAddressIsSigner(SIGNER);

//         assertEq(isSigner, false);
//     }

//     function testUserShouldNotBeAbleToRemoveSigner(address user) public {
//         address owner = proofOfPassportRegister.owner();
//         // Exclude the owner from the fuzzed user addresses
//         vm.assume(user != owner);

//         vm.prank(user);
//         vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
//         proofOfPassportRegister.removeSigner(SIGNER);
//     }

//     /*//////////////////////////////////////////////////////////////
//                                 VERIFIER
//     //////////////////////////////////////////////////////////////*/
//     function testOwnerShouldBeAbleToAddVerifierAndItShouldEmitAnEvent() public {
//         address owner = proofOfPassportRegister.owner();

//         Verifier_register_sha256WithRSASSAPSS_65537 mockVerifier = new Verifier_register_sha256WithRSASSAPSS_65537();

//         vm.expectEmit(true, true, false, false, address(proofOfPassportRegister));
//         emit VerifierSet(SECOND_SIGNATURE_ALGORITHM, address(mockVerifier));

//         vm.prank(owner);
//         proofOfPassportRegister.setVerifier(SECOND_SIGNATURE_ALGORITHM, address(mockVerifier));

//         address verifier = proofOfPassportRegister.getVerifier(SECOND_SIGNATURE_ALGORITHM);

//         assertEq(verifier, address(mockVerifier));
//     }

//     function testOwnerShouldNotBeAbleToAddVerifierWithAddress0() public {
//         address owner = proofOfPassportRegister.owner();

//         vm.prank(owner);

//         vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__ZeroAddress.selector);
//         proofOfPassportRegister.setVerifier(SECOND_SIGNATURE_ALGORITHM, address(0));
//     }

//     function testOwnerShouldNotBeAbleToAddWrongVerifierContract(address notAContract) public {
//         // Skip test if 'notAContract' is actually a contract
//         vm.assume(notAContract.code.length == 0);
//         // Also, ensure it's not the zero address to avoid overlapping with other tests
//         vm.assume(notAContract != address(0));

//         address owner = proofOfPassportRegister.owner();

//         vm.prank(owner);

//         vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__NotAContract.selector);
//         proofOfPassportRegister.setVerifier(SECOND_SIGNATURE_ALGORITHM, notAContract);
//     }

//     function testOwnerShouldNotBeAbleToAddVerifierWithInvalidVerifier() public {
//         address owner = proofOfPassportRegister.owner();

//         vm.prank(owner);

//         vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__InvalidVerifier.selector);
//         proofOfPassportRegister.setVerifier(SECOND_SIGNATURE_ALGORITHM, address(proofOfPassportRegister));
//     }

//     function testUserShouldNotBeAbleToAddVerifier(address user) public {
//         address owner = proofOfPassportRegister.owner();
//         // Exclude the owner from the fuzzed user addresses
//         vm.assume(user != owner);

//         Verifier_register_sha256WithRSASSAPSS_65537 mockVerifier = new Verifier_register_sha256WithRSASSAPSS_65537();

//         vm.prank(user);
//         vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
//         proofOfPassportRegister.setVerifier(SECOND_SIGNATURE_ALGORITHM, address(mockVerifier));
//     }

//     function testOwnerShouldBeAbleToRemoveVerifier() public {
//         address owner = proofOfPassportRegister.owner();

//         vm.prank(owner);
//         proofOfPassportRegister.removeVerifier(SIGNATURE_ALGORITHM);

//         address verifier = proofOfPassportRegister.getVerifier(SIGNATURE_ALGORITHM);

//         assertEq(verifier, address(0));
//     }

//     function testShouldEmitEventIfVerifierRemovedSuccesfully() public {
//         address owner = proofOfPassportRegister.owner();

//         vm.expectEmit(true, false, true, false, address(proofOfPassportRegister));
//         emit VerifierRemoved(SIGNATURE_ALGORITHM);

//         vm.prank(owner);
//         proofOfPassportRegister.removeVerifier(SIGNATURE_ALGORITHM);
//     }

//     function testUserShouldNotBeAbleToRemoveVerifier(address user) public {
//         address owner = proofOfPassportRegister.owner();
//         // Exclude the owner from the fuzzed user addresses
//         vm.assume(user != owner);

//         vm.prank(user);
//         vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
//         proofOfPassportRegister.removeVerifier(SIGNATURE_ALGORITHM);
//     }

//     /*//////////////////////////////////////////////////////////////
//                              REGISTER WITH PROOF
//     //////////////////////////////////////////////////////////////*/
//     function testSignerShouldBeAbleToRegisterProofAndEmitEventCorrectly() public {
//         address RECIPIENT = makeAddr("recipient");

//         vm.expectEmit(true, true, false, false, address(proofOfPassportRegister));
//         emit RecipientRegistered(RECIPIENT, NULLIFIER);

//         vm.prank(SIGNER);
//         proofOfPassportRegister.registerWithProof(proof, SIGNATURE_ALGORITHM, RECIPIENT);

//         bool isRegistered = proofOfPassportRegister.isRegistered(NULLIFIER, RECIPIENT);
//         assertEq(isRegistered, true);
//     }

//     function testUserShouldNotBeAbleToRegisterWithProof(address user) public {
//         address RECIPIENT = makeAddr("recipient");
//         // Exclude the signer from the fuzzed user addresses
//         vm.assume(user != SIGNER);

//         vm.prank(user);
//         vm.expectRevert(
//             abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__CallerNotSigner.selector)
//         );
//         proofOfPassportRegister.registerWithProof(proof, SIGNATURE_ALGORITHM, RECIPIENT);
//     }

//     function testShouldRevertIfRegisterTwice() public {
//         address RECIPIENT = makeAddr("recipient");

//         vm.prank(SIGNER);
//         proofOfPassportRegister.registerWithProof(proof, SIGNATURE_ALGORITHM, RECIPIENT);

//         vm.prank(SIGNER);
//         vm.expectRevert(
//             abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__ProofAlreadyRegistered.selector)
//         );
//         proofOfPassportRegister.registerWithProof(proof, SIGNATURE_ALGORITHM, RECIPIENT);
//     }

//     function testShouldRevertIfInvalidSignatureAlgorithmWhileRegistering(uint256 signatureAlgorithm) public {
//         address RECIPIENT = makeAddr("recipient");
//         // Exclude the valid signature algorithm from the fuzzed inputs
//         vm.assume(signatureAlgorithm != SIGNATURE_ALGORITHM);

//         vm.prank(SIGNER);
//         vm.expectRevert(
//             abi.encodeWithSelector(
//                 IProofOfPassportRegister.ProofOfPassportRegister__UnsupportedSignatureAlgorithm.selector
//             )
//         );
//         proofOfPassportRegister.registerWithProof(proof, signatureAlgorithm, RECIPIENT);
//     }

//     function testShouldRevertIfInvalidAttestationIdWhileRegistering(uint256 newAttestationId) public {
//         address RECIPIENT = makeAddr("recipient");

//         vm.assume(newAttestationId != ATTESTATION_ID);
//         proof.attestation_id = newAttestationId;

//         vm.prank(SIGNER);
//         vm.expectRevert(
//             abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__InvalidAttestationId.selector)
//         );
//         proofOfPassportRegister.registerWithProof(proof, SIGNATURE_ALGORITHM, RECIPIENT);
//     }

//     function testShouldRevertIfInvalidProofWhileRegistering() public {
//         address RECIPIENT = makeAddr("recipient");

//         vm.mockCall(
//             verifiers[0],
//             abi.encodeWithSelector(Verifier_register_sha256WithRSASSAPSS_65537(verifiers[0]).verifyProof.selector),
//             abi.encode(false)
//         );

//         vm.prank(SIGNER);
//         vm.expectRevert(abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__InvalidProof.selector));
//         proofOfPassportRegister.registerWithProof(proof, SIGNATURE_ALGORITHM, RECIPIENT);
//     }

//     /*//////////////////////////////////////////////////////////////
//                              VALIDATE PROOF
//     //////////////////////////////////////////////////////////////*/
//     function testShouldValidateProofAndEmitEvent() public {
//         address RECIPIENT = makeAddr("recipient");

//         vm.prank(SIGNER);
//         proofOfPassportRegister.registerWithProof(proof, SIGNATURE_ALGORITHM, RECIPIENT);

//         bool isValid = proofOfPassportRegister.validateProof(proof, SIGNATURE_ALGORITHM, RECIPIENT);

//         assertEq(isValid, true);
//     }

//     function testShouldRevertIfNotRegisteredWhileValidating() public {
//         address RECIPIENT = makeAddr("recipient");

//         vm.expectRevert(
//             abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__NullifierDoesNotExist.selector)
//         );
//         proofOfPassportRegister.validateProof(proof, SIGNATURE_ALGORITHM, RECIPIENT);
//     }

//     function testShouldRevertIfInvalidSignatureAlgorithmWhileValidating(uint256 newSignatureAlgorithm) public {
//         address RECIPIENT = makeAddr("recipient");
//         vm.assume(newSignatureAlgorithm != SIGNATURE_ALGORITHM);

//         vm.prank(SIGNER);
//         proofOfPassportRegister.registerWithProof(proof, SIGNATURE_ALGORITHM, RECIPIENT);

//         vm.expectRevert(
//             abi.encodeWithSelector(
//                 IProofOfPassportRegister.ProofOfPassportRegister__UnsupportedSignatureAlgorithm.selector
//             )
//         );
//         proofOfPassportRegister.validateProof(proof, newSignatureAlgorithm, RECIPIENT);
//     }

//     function testShouldRevertIfInvalidAttestationIdWhileValidating(uint256 newAttestationId) public {
//         address RECIPIENT = makeAddr("recipient");
//         vm.assume(newAttestationId != ATTESTATION_ID);

//         vm.prank(SIGNER);
//         proofOfPassportRegister.registerWithProof(proof, SIGNATURE_ALGORITHM, RECIPIENT);

//         proof.attestation_id = newAttestationId;

//         vm.expectRevert(
//             abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__InvalidAttestationId.selector)
//         );
//         proofOfPassportRegister.validateProof(proof, SIGNATURE_ALGORITHM, RECIPIENT);
//     }

//     function testShouldRevertIfInvalidProofWhileValidating() public {
//         address RECIPIENT = makeAddr("recipient");

//         vm.prank(SIGNER);
//         proofOfPassportRegister.registerWithProof(proof, SIGNATURE_ALGORITHM, RECIPIENT);

//         vm.mockCall(
//             verifiers[0],
//             abi.encodeWithSelector(Verifier_register_sha256WithRSASSAPSS_65537(verifiers[0]).verifyProof.selector),
//             abi.encode(false)
//         );

//         vm.expectRevert(abi.encodeWithSelector(IProofOfPassportRegister.ProofOfPassportRegister__InvalidProof.selector));
//         proofOfPassportRegister.validateProof(proof, SIGNATURE_ALGORITHM, RECIPIENT);
//     }
// }
