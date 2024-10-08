// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {Script} from "forge-std/Script.sol";
import {VerifierProveRSAPSS65537SHA256} from "../../../../src/verifiers/prove/Verifier_prove_rsapss_65537_sha256.sol";

contract TestVerifierRegisterSha256RSAPSS65537 is Test, Script {
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
        uint256[2] memory a = [
            uint256(0x16fb0440db68a5b76c214955b4b4a589d0975bc0705d02a9f1188ef94d79d818),
            uint256(0x18c88dcb7dee8a5cec63ab825ddcd305e328cd3969f2f5a8a10b29455b319f88)
        ];
        uint256[2][2] memory b = [
            [
                uint256(0x023758e8999d27fa43fd8c1b68e465db27a5461aa384ffe4c5e2998a089a7fae),
                uint256(0x013abb47f253ec15fadd53bd0982d001ce576b2d763ff087c1803b34403bbdf7)
            ],
            [
                uint256(0x15da986885dec3f51871e480e0026e61ba7df8a23410c8061016b37002e9b189),
                uint256(0x2e9945d6308f2bb6470b00e6e7411f2852302ff3e43fb67444c8a4494ed792b5)
            ]
        ];
        uint256[2] memory c = [
            uint256(0x244fdd6f2fb3d85a9b1668a5271d75bff184c714b06895af5681cb98b1209013),
            uint256(0x0df147be287b12b40944104d7586da6d78b4ceac7ea1bafd5ecd4e0a874ebb0f)
        ];
        uint256[45] memory pubSignals = [
            uint256(0x0000000000000000000000000000000000000000000000000000000000000001),
            uint256(0x0000000000000000000000000000000000000000000000000000000000000000),
            uint256(0x0000000000000000000000000000000000000000000000000000000000000000),
            uint256(0x0000000038310000000000000000000000000000000000000000000000000000),
            uint256(0x19605cc642747f3b686cdc0cf0ddcf636deb10db3fb8b7a9209200c866e67a62),
            uint256(0x0000000000000000000000000000000000000000000000001402946428b4f511),
            uint256(0x000000000000000000000000000000000000000000000000f7888e17e6334b03),
            uint256(0x000000000000000000000000000000000000000000000000c3af317e70a9ebb4),
            uint256(0x000000000000000000000000000000000000000000000000751dc3fdf81cf16e),
            uint256(0x0000000000000000000000000000000000000000000000004fc85174df3c0ebb),
            uint256(0x000000000000000000000000000000000000000000000000715f1893c4c90ef0),
            uint256(0x0000000000000000000000000000000000000000000000006e1382bd0c8064cd),
            uint256(0x000000000000000000000000000000000000000000000000d63bb36b91452753),
            uint256(0x000000000000000000000000000000000000000000000000fc6d05970c9bca91),
            uint256(0x0000000000000000000000000000000000000000000000008d84084f0043acd2),
            uint256(0x00000000000000000000000000000000000000000000000045681a0cf06c6f83),
            uint256(0x000000000000000000000000000000000000000000000000becc8d6fd1499aec),
            uint256(0x000000000000000000000000000000000000000000000000acfef338044f482d),
            uint256(0x000000000000000000000000000000000000000000000000e9d8b428337c0404),
            uint256(0x000000000000000000000000000000000000000000000000e90dfe55fd68fb90),
            uint256(0x000000000000000000000000000000000000000000000000a5149589a795b7c4),
            uint256(0x0000000000000000000000000000000000000000000000007a006a746be3726b),
            uint256(0x000000000000000000000000000000000000000000000000aff4cb7688e522b3),
            uint256(0x000000000000000000000000000000000000000000000000d57df3abd6eb1170),
            uint256(0x000000000000000000000000000000000000000000000000fd3d6124bc10dfe3),
            uint256(0x00000000000000000000000000000000000000000000000066835ce3dbe6b647),
            uint256(0x000000000000000000000000000000000000000000000000a22beda540d1f620),
            uint256(0x000000000000000000000000000000000000000000000000095e5aa9405be553),
            uint256(0x000000000000000000000000000000000000000000000000f3685db5b6bd48ea),
            uint256(0x000000000000000000000000000000000000000000000000ccdbc40af2feb0f9),
            uint256(0x000000000000000000000000000000000000000000000000a3b62190ca1a2308),
            uint256(0x0000000000000000000000000000000000000000000000008347e60d171c42f5),
            uint256(0x000000000000000000000000000000000000000000000000740a3806f568f057),
            uint256(0x000000000000000000000000000000000000000000000000557e6eb412cc5857),
            uint256(0x0000000000000000000000000000000000000000000000009465792fb0488b44),
            uint256(0x000000000000000000000000000000000000000000000000c078c4ae20ffc713),
            uint256(0x000000000000000000000000000000000000000000000000c1c7212416c29d43),
            uint256(0x0000000000000000000000000000000000000000000000000000000000000418),
            uint256(0x0000000000000000000000000000000000000000000000000000000000000002),
            uint256(0x0000000000000000000000000000000000000000000000000000000000000004),
            uint256(0x0000000000000000000000000000000000000000000000000000000000000001),
            uint256(0x0000000000000000000000000000000000000000000000000000000000000000),
            uint256(0x0000000000000000000000000000000000000000000000000000000000000000),
            uint256(0x0000000000000000000000000000000000000000000000000000000000000004),
            uint256(0x0000000000000000000000000000000000000000000000000000000000000000)
        ];

        bool isVerified = verifier.verifyProof(a, b, c, pubSignals);

        assertEq(isVerified, true);
    }
}