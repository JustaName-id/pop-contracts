// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {CodeConstants} from "../../script/HelperConfig.s.sol";
import {TestCodeConstants} from "../../script/TestHelperConfig.s.sol";
import {ProofOfPassportRegister} from "../../src/ProofOfPassportRegister.sol";
import {ProofOfPassportRegisterHandler} from "./ProofOfPassportRegisterHandler.t.sol";
import {DeployProofOfPassportRegister} from "../../script/DeployProofOfPassportRegister.s.sol";
import {IProofOfPassportRegister} from "../../src/interfaces/IProofOfPassportRegister.sol";
import {VerifierProveRSA65537SHA1} from "../../src/verifiers/prove/Verifier_prove_rsa_65537_sha1.sol";
import {VerifierProveRSAPSS65537SHA256} from "../../src/verifiers/prove/Verifier_prove_rsapss_65537_sha256.sol";

contract ProofOfPassportRegisterInvariant is StdInvariant, Test, CodeConstants, TestCodeConstants {
    ProofOfPassportRegister proofOfPassportRegister;
    HelperConfig helperConfig;
    ProofOfPassportRegisterHandler handler;

    VerifierProveRSA65537SHA1 public verifierProveRSA65537SHA1;
    VerifierProveRSAPSS65537SHA256 public verifierProveRSAPSS65537SHA256;

    uint256[] private validSignatureAlgorithms = [1, 3, 4];

    function setUp() external {
        console.log("Starting setUp");
        DeployProofOfPassportRegister deployer = new DeployProofOfPassportRegister();
        (proofOfPassportRegister, helperConfig) = deployer.run();
        console.log("Deployment completed");

        vm.startBroadcast();
        verifierProveRSA65537SHA1 = new VerifierProveRSA65537SHA1();
        verifierProveRSAPSS65537SHA256 = new VerifierProveRSAPSS65537SHA256();
        vm.stopBroadcast();
        console.log("Verifiers created");

        handler = new ProofOfPassportRegisterHandler(proofOfPassportRegister);
        console.log("Handler created");

        address owner = proofOfPassportRegister.owner();
        console.log("Owner address: %s", owner);

        vm.startPrank(owner);
        proofOfPassportRegister.setSigner(address(handler));
        proofOfPassportRegister.setVerifier(
            SIGNATURE_ALGORITHM_RSA_65537_SHA1, address(verifierProveRSA65537SHA1), NULLIFIER_INDEX_IN_PUB_SIGNAL
        );
        proofOfPassportRegister.setVerifier(
            SIGNATURE_ALGORITHM_RSA_PSS_65537_SHA256,
            address(verifierProveRSAPSS65537SHA256),
            NULLIFIER_INDEX_IN_PUB_SIGNAL
        );
        vm.stopPrank();
        console.log("Signer and verifiers set");

        targetContract(address(handler));
        console.log("Target contract set");
    }

    function invariant_onlyRegisteredAddressesAreValid() public view {
        for (uint256 i = 0; i < validSignatureAlgorithms.length; i++) {
            uint256 signatureAlgorithm = validSignatureAlgorithms[i];
            address[] memory registeredAddresses = handler.getRegisteredAddresses(signatureAlgorithm);

            for (uint256 j = 0; j < registeredAddresses.length; j++) {
                IProofOfPassportRegister.Proof memory proof = handler.getProof(signatureAlgorithm);
                uint256 nullifier = handler.getNullifier(proof);
                assertTrue(proofOfPassportRegister.isRegistered(nullifier, registeredAddresses[j]));
                assertTrue(proofOfPassportRegister.validateProof(proof, registeredAddresses[j]));
            }
        }
    }

    function invariant_getterFunctionsShouldNeverRevert() public view {
        uint256 randomSignatureAlgorithm = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao, msg.sender)));
        address randomAddress = address(uint160(randomSignatureAlgorithm));
        
        proofOfPassportRegister.getVerifier(randomSignatureAlgorithm);
        proofOfPassportRegister.getNullifierIndex(randomSignatureAlgorithm);
        proofOfPassportRegister.checkIfAddressIsSigner(randomAddress);
    }
}
