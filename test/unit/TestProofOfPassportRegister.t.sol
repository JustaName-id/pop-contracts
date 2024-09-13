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

contract TestProofOfPassportRegister is Test, Script, CodeConstants {
    ProofOfPassportRegister public proofOfPassportRegister;
    HelperConfig public helperConfig;

    uint256 attestationI;
    uint256 merkleRoot;
    uint256[] signatureAlgorithms;
    address[] verifiers;
    address[] signers;

    uint256 public constant SECOND_SIGNATURE_ALGORITHM = 2;

    address SIGNER = makeAddr("signer");
    address NOT_VERIFIER_CONTRACT = makeAddr("notVerifierContract");

    event Register(address indexed recipient, uint256 indexed merkle_root, uint256 indexed nullifier);

    event VerifierSet(uint256 indexed signature_algorithm, address indexed verifier);

    event CSCAVerifierSet(uint256 indexed signature_algorithm, address indexed verifier);

    event SignerSet(address indexed signer);

    event SignerRemoved(address indexed signer);

    event VerifierRemoved(uint256 indexed signature_algorithm);

    event CSCAVerifierRemoved(uint256 indexed signature_algorithm);

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        DeployProofOfPassportRegister deployer = new DeployProofOfPassportRegister();
        (proofOfPassportRegister, helperConfig) = deployer.run();
        HelperConfig.NetworkConfig memory config = helperConfig.getConfig();

        attestationI = config.attestationId;
        merkleRoot = config.merkleRoot;
        signatureAlgorithms = config.signatureAlgorithms;
        verifiers = config.verifiers;
        signers = config.signers;
    }

    /*//////////////////////////////////////////////////////////////
                             INITIAL VALUES
    //////////////////////////////////////////////////////////////*/
    function testInitialValues() public view {
        uint256 attestationId = proofOfPassportRegister.getAttestationId();
        bool isSigner = proofOfPassportRegister.checkIfAddressIsSigner(SIGNER);
        address verifier = proofOfPassportRegister.getVerifier(SIGNATURE_ALGORITHM);

        assertEq(attestationId, attestationI);
        assertEq(isSigner, true);
        assertNotEq(verifier, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                                 SIGNER
    //////////////////////////////////////////////////////////////*/
    function testAddingNewSignerAsOwner() public {
        address SIGNER2 = makeAddr("signer2");

        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);
        proofOfPassportRegister.setSigner(SIGNER2);

        bool isSigner = proofOfPassportRegister.checkIfAddressIsSigner(SIGNER2);

        assertEq(isSigner, true);
    }

    function testAddingNewSignerAsUserWillFail() public {
        address SIGNER2 = makeAddr("signer2");

        address USER = makeAddr("user");

        vm.prank(USER);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, USER));
        proofOfPassportRegister.setSigner(SIGNER2);
    }

    function testAddingAddress0AsSignerWillFail() public {
        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);

        vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__ZeroAddress.selector);
        proofOfPassportRegister.setSigner(address(0));
    }

    function testShouldEmitEventIfNewSignerAddedSuccesfully() public {
        address owner = proofOfPassportRegister.owner();

        vm.expectEmit(true, false, false, false, address(proofOfPassportRegister));
        emit SignerSet(SIGNER);

        vm.prank(owner);
        proofOfPassportRegister.setSigner(SIGNER);
    }

    function testOwnerShouldBeAbleToRemoveSigner() public {
        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);
        proofOfPassportRegister.removeSigner(SIGNER);

        bool isSigner = proofOfPassportRegister.checkIfAddressIsSigner(SIGNER);

        assertEq(isSigner, false);
    }

    function testUserShouldNotBeAbleToRemoveSigner() public {
        address USER = makeAddr("user");

        vm.prank(USER);

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, USER));
        proofOfPassportRegister.removeSigner(SIGNER);
    }

    function testShouldEmitEventIfSignerRemovedSuccesfully() public {
        address owner = proofOfPassportRegister.owner();

        vm.expectEmit(true, false, false, false, address(proofOfPassportRegister));
        emit SignerRemoved(SIGNER);

        vm.prank(owner);
        proofOfPassportRegister.removeSigner(SIGNER);
    }

    /*//////////////////////////////////////////////////////////////
                                VERIFIER
    //////////////////////////////////////////////////////////////*/
    function testOwnerShouldBeAbleToAddVerifier() public {
        address owner = proofOfPassportRegister.owner();

        Verifier_register_sha256WithRSASSAPSS_65537 mockVerifier = new Verifier_register_sha256WithRSASSAPSS_65537();

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

    function testOwnerShouldNotBeAbleToAddWrongVerifierContract() public {
        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);

        vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__NotAContract.selector);
        proofOfPassportRegister.setVerifier(SECOND_SIGNATURE_ALGORITHM, NOT_VERIFIER_CONTRACT);
    }

    function testOwnerShouldNotBeAbleToAddVerifierWithInvalidVerifier() public {
        address owner = proofOfPassportRegister.owner();

        vm.prank(owner);

        vm.expectRevert(IProofOfPassportRegister.ProofOfPassportRegister__InvalidVerifier.selector);
        proofOfPassportRegister.setVerifier(SECOND_SIGNATURE_ALGORITHM, address(proofOfPassportRegister));
    }

    function testShouldEmitEventIfNewVerifierAddedSuccesfully() public {
        address owner = proofOfPassportRegister.owner();

        Verifier_register_sha256WithRSASSAPSS_65537 mockVerifier = new Verifier_register_sha256WithRSASSAPSS_65537();

        vm.expectEmit(true, true, false, false, address(proofOfPassportRegister));

        emit VerifierSet(SECOND_SIGNATURE_ALGORITHM, address(mockVerifier));

        vm.prank(owner);
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

    /*//////////////////////////////////////////////////////////////
                              VERIFIER CSCA
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                             REGISTER WITH PROOF
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                             VALIDATE PROOF
    //////////////////////////////////////////////////////////////*/
}
