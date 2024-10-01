// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {Script} from "forge-std/Script.sol";
import {Verifier_register_sha256WithRSASSAPSS_65537} from
    "../../../../src/verifiers/register/Verifier_register_sha256WithRSASSAPSS_65537.sol";

contract TestVerifierRegisterSha256WithRSASSAPSS65537 is Test, Script {
    Verifier_register_sha256WithRSASSAPSS_65537 public verifier;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        verifier = new Verifier_register_sha256WithRSASSAPSS_65537();
    }

    /*//////////////////////////////////////////////////////////////
                              Verify Proof
    //////////////////////////////////////////////////////////////*/
    function testShouldReturnFalseWhenInvalidProof() public view {
        bool isVerified = verifier.verifyProof(
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0), uint256(0), uint256(0)]
        );

        assertEq(isVerified, false);
    }
}
