// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {Script} from "forge-std/Script.sol";
import {Verifier_register_sha256WithRSAEncryption_65537} from
    "../../../../src/verifiers/register/Verifier_register_sha256WithRSAEncryption_65537.sol";

contract TestVerifierRegisterSha256RSA65537 is Test, Script {
    Verifier_register_sha256WithRSAEncryption_65537 public verifier;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/
    function setUp() public {
        verifier = new Verifier_register_sha256WithRSAEncryption_65537();
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

    function testShouldReturnTrueWhenValidProof() public view {
        bool isVerified = verifier.verifyProof(
            [
                uint256(8195835542678743783163226528371499988144935543750141575611340358896774454816),
                uint256(2209506788378118091568290365981136424645064544627281479743435248075396491661)
            ],
            [
                [
                    uint256(8893515179677263572942221505876027597210252218779842682394935123548654257899),
                    uint256(3061765629644253624353790004177413455741874666803304199456431156372590646663)
                ],
                [
                    uint256(1768627047223876624607667061139079154862543605011479322553011598571562978003),
                    uint256(13263412489830230622306227659845224001862213300485106861095745311490098958501)
                ]
            ],
            [
                uint256(765541449170223093348594833286465989565626510379675047078894361317277091164),
                uint256(17624079887804428923491403825622568085162246209499362015388791653787650647323)
            ],
            [
                uint256(20945984012239186224706207479848075322936319931499692551338730625273680564081),
                uint256(3024342369770083205277676417000541928218842535300840137930294206510168723413),
                uint256(9679099037931877108868525538868967848515342281134174602460750910095681194378),
                uint256(8518753152044246090169372947057357973469996808638122125210848696986717482788)
            ]
        );

        assertEq(isVerified, true);
    }
}
