// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {Script} from "forge-std/Script.sol";
import {Verifier_dsc_sha256_rsapss_2048} from "../../../../src/verifiers/dsc/Verifier_dsc_sha256_rsapss_2048.sol";

contract TestVerifierDscSha256RSAPSS2048 is Test, Script {

    Verifier_dsc_sha256_rsapss_2048 public verifier;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        verifier = new Verifier_dsc_sha256_rsapss_2048();
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