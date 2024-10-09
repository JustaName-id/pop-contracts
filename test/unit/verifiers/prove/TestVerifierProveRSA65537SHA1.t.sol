// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {Script} from "forge-std/Script.sol";
import {CodeConstants} from "../../../../script/HelperConfig.s.sol";
import {VerifierProveRSA65537SHA1} from "../../../../src/verifiers/prove/Verifier_prove_rsa_65537_sha1.sol";

contract TestVerifierRegisterSha165537 is Test, Script, CodeConstants {
    VerifierProveRSA65537SHA1 public verifier;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        verifier = new VerifierProveRSA65537SHA1();
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
        bool isVerified = verifier.verifyProof(
            SHA1_RSA_65537_PROOF.a, SHA1_RSA_65537_PROOF.b, SHA1_RSA_65537_PROOF.c, SHA1_RSA_65537_PROOF.pubSignals
        );

        assertEq(isVerified, true);
    }
}
