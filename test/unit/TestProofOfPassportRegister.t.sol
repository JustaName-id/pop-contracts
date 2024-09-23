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

    uint256 public constant SECOND_SIGNATURE_ALGORITHM = 2;
    uint256 public constant SECOND_CSCA_SIGNATURE_ALGORITHM = 2;

    uint256 public constant NEW_MERKLE_ROOT =
        97617982452311505471274934026898123532183481230970869414506856451449510095384;

    address SIGNER = makeAddr("signer");

    event Register(address indexed recipient, uint256 indexed merkle_root, uint256 indexed nullifier);

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

    function testUserShouldNotBeAbleToAddVerifier(address user) public {
        address owner = proofOfPassportRegister.owner();
        // Exclude the owner from the fuzzed user addresses
        vm.assume(user != owner);

        Verifier_register_sha256WithRSASSAPSS_65537 mockVerifier = new Verifier_register_sha256WithRSASSAPSS_65537();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        proofOfPassportRegister.setVerifier(SECOND_SIGNATURE_ALGORITHM, address(mockVerifier));
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

    function testOwnerShouldBeAbleToRemoveVerifierAndItShouldEmitEvent() public {
        address owner = proofOfPassportRegister.owner();

        vm.expectEmit(true, false, true, false, address(proofOfPassportRegister));
        emit CSCAVerifierRemoved(CSCA_SIGNATURE_ALGORITHM);

        vm.prank(owner);
        proofOfPassportRegister.removeCSCAVerifier(CSCA_SIGNATURE_ALGORITHM);

        address cscaVerifier = proofOfPassportRegister.getCSCAVerifier(CSCA_SIGNATURE_ALGORITHM);

        assertEq(cscaVerifier, address(0));
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

    /*//////////////////////////////////////////////////////////////
                             REGISTER WITH PROOF
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                             VALIDATE PROOF
    //////////////////////////////////////////////////////////////*/

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

    function shouldRevertIfSameRootIsSet() public {
        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);

        vm.expectRevert(MerkleTreeRegistry.MerkleTreeRegistry__SameRoot.selector);
        proofOfPassportRegister.setRoot(MERKLE_ROOT);
    }
}
