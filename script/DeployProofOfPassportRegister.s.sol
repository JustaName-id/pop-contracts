// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ProofOfPassportRegister} from "../src/ProofOfPassportRegister.sol";
import {HelperConfig, CodeConstants} from "./HelperConfig.s.sol";

contract DeployProofOfPassportRegister is Script, CodeConstants {
    function run() public returns (ProofOfPassportRegister, HelperConfig) {
        console.log("Deploying ProofOfPassportRegister");
        HelperConfig helperConfig = new HelperConfig();
        HelperConfig.NetworkConfig memory config = helperConfig.getConfig();

        vm.startBroadcast(config.deployerKey);
        ProofOfPassportRegister register = new ProofOfPassportRegister(
            config.signatureAlgorithms, config.verifiers, config.nullifiersIndexesInPubSigArray, config.signers
        );
        vm.stopBroadcast();
        return (register, helperConfig);
    }
}
