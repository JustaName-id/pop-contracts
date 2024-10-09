// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {Script} from "forge-std/Script.sol";
import {CodeConstants} from "../../../../script/HelperConfig.s.sol";
import {VerifierProveRSAPSS65537SHA256} from "../../../../src/verifiers/prove/Verifier_prove_rsapss_65537_sha256.sol";

contract TestVerifierRegisterSha256RSAPSS65537 is Test, Script, CodeConstants {
    VerifierProveRSAPSS65537SHA256 public verifier;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        verifier = new VerifierProveRSAPSS65537SHA256();
    }

    /*//////////////////////////////////////////////////////////////
                              Verify Proof
    //////////////////////////////////////////////////////////////*/
    function testShouldReturnFalseWhenInvalidProof() public view {
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        uint256[45] memory pubSignals;

        bool isVerified = verifier.verifyProof(a, b, c, pubSignals);

        assertEq(isVerified, false);
    }

    function testShouldReturnTrueWhenValidProof() public view {
        bool isVerified = verifier.verifyProof(SHA256_RSA_PSS_65537_PROOF.a, SHA256_RSA_PSS_65537_PROOF.b, SHA256_RSA_PSS_65537_PROOF.c, SHA256_RSA_PSS_65537_PROOF.pubSignals);

        assertEq(isVerified, true);
    }
}
