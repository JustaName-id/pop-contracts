// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {Verifier_register_sha256WithRSAEncryption_65537} from
    "../src/verifiers/register/Verifier_register_sha256WithRSAEncryption_65537.sol";
import {Verifier_dsc_sha256_rsa_2048} from "../src/verifiers/dsc/Verifier_dsc_sha256_rsa_2048.sol";

abstract contract CodeConstants {
    uint256 public constant MAINNET_ETH_CHAIN_ID = 1;
    uint256 public constant ETH_SEPOLIA_CHAIN_ID = 11155111;
    uint256 public constant LOCAL_CHAIN_ID = 31337;

    uint256 public constant ATTESTATION_ID =
        8518753152044246090169372947057357973469996808638122125210848696986717482788;
    uint256 public constant MERKLE_ROOT = 16265790307011125658362292627401518982983756210990787658744129014512572229764;

    uint256 public constant SIGNATURE_ALGORITHM = 1;
    uint256 public constant CSCA_SIGNATURE_ALGORITHM = 1;

    uint256[] public initialSignatureAlgorithms;
    address[] public initialVerifiers;
    uint256[] public initialCSCASignatureAlgorithms;
    address[] public initialCSCAVerifiers;

    address[] public initialSigners;

    uint256 public DEFAULT_ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address public DEFAULT_ANVIL_ADDRESS = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
}

contract HelperConfig is CodeConstants, Script {
    error HelperConfig__InvalidChainId();

    struct NetworkConfig {
        uint256 attestationId;
        uint256 merkleRoot;
        uint256[] signatureAlgorithms;
        address[] verifiers;
        uint256[] cscaSignatureAlgorithms;
        address[] cscaVerifiers;
        address[] signers;
        uint256 deployerKey;
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
        initialCSCASignatureAlgorithms.push(CSCA_SIGNATURE_ALGORITHM);

        // Get Signer
        address SIGNER = makeAddr("signer");

        initialSigners.push(SIGNER);

        // Deploy the verifier contract
        vm.startBroadcast();
        Verifier_register_sha256WithRSAEncryption_65537 sha256WithRSAEncryption =
            new Verifier_register_sha256WithRSAEncryption_65537();
        Verifier_dsc_sha256_rsa_2048 dsc_sha256_rsa_2048 = new Verifier_dsc_sha256_rsa_2048();
        vm.stopBroadcast();

        initialVerifiers.push(address(sha256WithRSAEncryption));
        initialCSCAVerifiers.push(address(dsc_sha256_rsa_2048));

        networkConfig = NetworkConfig({
            attestationId: ATTESTATION_ID,
            merkleRoot: MERKLE_ROOT,
            signatureAlgorithms: initialSignatureAlgorithms,
            verifiers: initialVerifiers,
            cscaSignatureAlgorithms: initialCSCASignatureAlgorithms,
            cscaVerifiers: initialCSCAVerifiers,
            signers: initialSigners,
            deployerKey: DEFAULT_ANVIL_KEY
        });

        return networkConfig;
    }
}
