// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {TestCodeConstants} from "../../script/TestHelperConfig.s.sol";
import {CodeConstants} from "../../script/HelperConfig.s.sol";
import {ProofOfPassportRegister} from "../../src/ProofOfPassportRegister.sol";
import {IProofOfPassportRegister} from "../../src/interfaces/IProofOfPassportRegister.sol";
import {VerifierProveRSA65537SHA256} from "../../src/verifiers/prove/Verifier_prove_rsa_65537_sha256.sol";

contract ProofOfPassportRegisterHandler is Test, TestCodeConstants, CodeConstants {
    ProofOfPassportRegister s_register;
    address[][] private registeredAddresses = new address[][](5);

    constructor(ProofOfPassportRegister _register) {
        s_register = _register;
    }

    function registerProof(address recipient, uint256 signatureAlgorithmSeed) public {
        if (recipient == address(0)) {
            return;
        }

        uint256 signatureAlgorithm = _getSignatureAlgorithmBySeed(signatureAlgorithmSeed);

        IProofOfPassportRegister.Proof memory proof = getProof(signatureAlgorithm);
        uint256 nullifier = getNullifier(proof);

        if (!s_register.isRegistered(nullifier, recipient)) {
            s_register.registerWithProof(proof, recipient);
            registeredAddresses[signatureAlgorithm].push(recipient);
        }
    }

    function setSigner(address _signer) public {
        if (_signer == address(0)) {
            return;
        }

        address owner = s_register.owner();

        vm.prank(owner);
        s_register.setSigner(_signer);
    }

    function removeSigner(address _signer) public {
        bool isSigner = s_register.checkIfAddressIsSigner(_signer);

        if (isSigner) {
            address owner = s_register.owner();

            vm.prank(owner);
            s_register.removeSigner(_signer);
        }
    }

    function removeVerifier(uint256 signatureAlgorithm) public {
        if (signatureAlgorithm == 1 || signatureAlgorithm == 3 || signatureAlgorithm == 4) {
            return;
        }

        address verifier = s_register.getVerifier(signatureAlgorithm);

        if (verifier == address(0)) {
            return;
        }

        address owner = s_register.owner();

        vm.prank(owner);
        s_register.removeVerifier(signatureAlgorithm);
    }

    function setVerifier(uint256 signatureAlgorithm) public {
        if (signatureAlgorithm == 1 || signatureAlgorithm == 3 || signatureAlgorithm == 4) {
            return;
        }

        address owner = s_register.owner();

        VerifierProveRSA65537SHA256 newVerifier = new VerifierProveRSA65537SHA256();

        vm.prank(owner);
        s_register.setVerifier(signatureAlgorithm, address(newVerifier), NULLIFIER_INDEX_IN_PUB_SIGNAL);
    }

    function getRegisteredAddresses(uint256 signatureAlgorithm) public view returns (address[] memory) {
        return registeredAddresses[signatureAlgorithm];
    }

    function getRegisteredAddressesCount(uint256 signatureAlgorithm) public view returns (uint256) {
        return registeredAddresses[signatureAlgorithm].length;
    }

    function getNullifier(IProofOfPassportRegister.Proof memory proof) public view returns (uint256) {
        uint256 signatureAlgorithm = proof.pubSignals[SIGNATURE_ALGORITHM_INDEX_IN_PUB_SIGNALS];
        uint256 nullifierIndex = s_register.getNullifierIndex(signatureAlgorithm);
        return proof.pubSignals[nullifierIndex];
    }

    function getProof(uint256 signatureAlgorithm) public view returns (IProofOfPassportRegister.Proof memory) {
        if (signatureAlgorithm == 1) {
            return SHA256_RSA_65537_PROOF;
        } else if (signatureAlgorithm == 3) {
            return SHA1_RSA_65537_PROOF;
        } else if (signatureAlgorithm == 4) {
            return SHA256_RSA_PSS_65537_PROOF;
        } else {
            revert("Invalid signature algorithm");
        }
    }

    function _getSignatureAlgorithmBySeed(uint256 signatureAlgorithm) private pure returns (uint256) {
        if (signatureAlgorithm % 3 == 0) {
            return 1;
        } else if (signatureAlgorithm % 3 == 1) {
            return 3;
        }
        return 4;
    }
}
