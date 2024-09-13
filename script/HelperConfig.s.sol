// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {Verifier_register_sha256WithRSAEncryption_65537} from
    "../src/verifiers/register/Verifier_register_sha256WithRSAEncryption_65537.sol";

abstract contract CodeConstants {
    uint256 public constant MAINNET_ETH_CHAIN_ID = 1;
    uint256 public constant ETH_SEPOLIA_CHAIN_ID = 11155111;
    uint256 public constant LOCAL_CHAIN_ID = 31337;

    uint256 public constant ATTESTATION_ID =
        8518753152044246090169372947057357973469996808638122125210848696986717482788;
    uint256 public constant MERKLE_ROOT = 16265790307011125658362292627401518982983756210990787658744129014512572229764;
    uint256 public constant SIGNATURE_ALGORITHM = 1;
    uint256[] public initialSignatureAlgorithms;
    address[] public initialVerifiers;
    address[] public initialSigners;
}

contract HelperConfig is CodeConstants, Script {
    error HelperConfig__InvalidChainId();

    struct NetworkConfig {
        uint256 attestationId;
        uint256 merkleRoot;
        uint256[] signatureAlgorithms;
        address[] verifiers;
        address[] signers;
    }

    NetworkConfig public networkConfig;
    mapping(uint256 => NetworkConfig) public networkConfigs;

    constructor() {
        networkConfigs[LOCAL_CHAIN_ID] = getOrCreateAnvilEthConfig();
    }

    function getConfigByChainId(uint256 chainId) public returns (NetworkConfig memory) {
        if (networkConfig.verifiers.length > 0 && networkConfigs[chainId].verifiers[0] != address(0)) {
            return networkConfigs[chainId];
        } else if (chainId == LOCAL_CHAIN_ID) {
            return getOrCreateAnvilEthConfig();
        } else {
            revert HelperConfig__InvalidChainId();
        }
    }

    function getConfig() public returns (NetworkConfig memory) {
        return getConfigByChainId(block.chainid);
    }

    function getOrCreateAnvilEthConfig() public returns (NetworkConfig memory) {
        // Check to see if we set an active network config
        if (networkConfig.verifiers.length > 0 && networkConfig.verifiers[0] != address(0)) {
            return networkConfig;
        }

        initialSignatureAlgorithms.push(SIGNATURE_ALGORITHM);

        // Get Signer
        address SIGNER = makeAddr("signer");

        initialSigners.push(SIGNER);

        // Deploy the verifier contract
        vm.startBroadcast();
        Verifier_register_sha256WithRSAEncryption_65537 sha256WithRSAEncryption =
            new Verifier_register_sha256WithRSAEncryption_65537();
        vm.stopBroadcast();

        initialVerifiers.push(address(sha256WithRSAEncryption));

        networkConfig = NetworkConfig({
            attestationId: ATTESTATION_ID,
            merkleRoot: MERKLE_ROOT,
            signatureAlgorithms: initialSignatureAlgorithms,
            verifiers: initialVerifiers,
            signers: initialSigners
        });

        return networkConfig;
    }
}
