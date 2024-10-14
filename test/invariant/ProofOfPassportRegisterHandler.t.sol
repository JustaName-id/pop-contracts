// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {TestCodeConstants} from "../../script/TestHelperConfig.s.sol";
import {CodeConstants} from "../../script/HelperConfig.s.sol";
import {IProofOfPassportRegister} from "../../src/interfaces/IProofOfPassportRegister.sol";

contract ProofOfPassportRegisterHandler is Test, TestCodeConstants, CodeConstants {
    IProofOfPassportRegister s_register;
    address[][] private registeredAddresses;

    constructor(IProofOfPassportRegister _register) {
        s_register = _register;
        registeredAddresses = new address[][](5);
    }

    function registerProof(address recipient, uint256 _signatureAlgorithm) public {
        vm.assume(recipient != address(0));
        console.log("registerProof called with recipient: %s, _signatureAlgorithm: %d", recipient, _signatureAlgorithm);

        uint256 signatureAlgorithm = _getSignatureAlgorithm(_signatureAlgorithm);

        console.log("Registering proof for signature algorithm: %d", signatureAlgorithm);

        IProofOfPassportRegister.Proof memory proof = getProof(signatureAlgorithm);
        uint256 nullifier = getNullifier(proof);

        if (!s_register.isRegistered(nullifier, recipient)) {
            s_register.registerWithProof(proof, recipient);
            registeredAddresses[signatureAlgorithm].push(recipient);
        }
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

    function _getSignatureAlgorithm(uint256 signatureAlgorithm) private pure returns (uint256) {
        if (signatureAlgorithm % 3 == 0) {
            return 1;
        } else if (signatureAlgorithm % 3 == 1) {
            return 3;
        }
        return 4;
    }
}
