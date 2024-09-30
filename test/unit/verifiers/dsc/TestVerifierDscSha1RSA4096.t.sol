// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {Script} from "forge-std/Script.sol";
import {Verifier_dsc_sha1_rsa_4096} from "../../../../src/verifiers/dsc/Verifier_dsc_sha1_rsa_4096.sol";

contract TestVerifierDscSha1RSA4096 is Test, Script {
    Verifier_dsc_sha1_rsa_4096 public verifier;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        verifier = new Verifier_dsc_sha1_rsa_4096();
    }

    /*//////////////////////////////////////////////////////////////
                              Verify Proof
    //////////////////////////////////////////////////////////////*/
    function testShouldReturnFalseWhenInvalidProof() public view {
        bool isVerified = verifier.verifyProof(
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0)]
        );

        assertEq(isVerified, false);
    }
}
