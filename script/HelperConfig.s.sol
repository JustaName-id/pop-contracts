// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {VerifierProveRSA65537SHA256} from "../src/verifiers/prove/Verifier_prove_rsa_65537_sha256.sol";
import {VerifierProveRSA65537SHA1} from "../src/verifiers/prove/Verifier_prove_rsa_65537_sha1.sol";
import {VerifierProveRSAPSS65537SHA256} from "../src/verifiers/prove/Verifier_prove_rsapss_65537_sha256.sol";
import {IProofOfPassportRegister} from "../src/interfaces/IProofOfPassportRegister.sol";

abstract contract CodeConstants {
    uint256 public constant MAINNET_ETH_CHAIN_ID = 1;
    uint256 public constant BASE_SEPOLIA_CHAIN_ID = 84532;
    uint256 public constant ETH_SEPOLIA_CHAIN_ID = 11155111;
    uint256 public constant LOCAL_CHAIN_ID = 31337;

    uint256 public constant SIGNATURE_ALGORITHM_RSA_65537_SHA256 = 1;
    uint256 public constant SIGNATURE_ALGORITHM_RSA_65537_SHA1 = 3;
    uint256 public constant SIGNATURE_ALGORITHM_RSA_PSS_65537_SHA256 = 4;

    uint256 public constant NULLIFIER_INDEX_IN_PUB_SIGNAL = 4;

    uint256 public constant SIGNATURE_ALGORITHM_INDEX_IN_PUB_SIGNALS = 0;

    uint256[] public initialSignatureAlgorithms;
    address[] public initialVerifiers;
    uint256[] public initialNullifiersIndexesInPubSigArray;
    address[] public initialSigners;
}

contract HelperConfig is CodeConstants, Script {
    error HelperConfig__InvalidChainId();

    struct NetworkConfig {
        uint256[] signatureAlgorithms;
        address[] verifiers;
        uint256[] nullifiersIndexesInPubSigArray;
        address[] signers;
    }

    function getConfigByChainId(uint256 chainId) public returns (NetworkConfig memory) {
        if (chainId == LOCAL_CHAIN_ID) {
            return getOrCreateAnvilEthConfig();
        } else if (chainId == ETH_SEPOLIA_CHAIN_ID) {
            return getOrCreateSepoliaConfig();
        } else if (chainId == BASE_SEPOLIA_CHAIN_ID) {
            return getOrCreateSepoliaConfig();
        } else {
            revert HelperConfig__InvalidChainId();
        }
    }

    function getConfig() public returns (NetworkConfig memory) {
        return getConfigByChainId(block.chainid);
    }

    function getOrCreateAnvilEthConfig() public returns (NetworkConfig memory) {
        initialSignatureAlgorithms.push(SIGNATURE_ALGORITHM_RSA_65537_SHA256);

        // Get Signer
        address SIGNER = makeAddr("signer");

        initialSigners.push(SIGNER);
        initialNullifiersIndexesInPubSigArray.push(NULLIFIER_INDEX_IN_PUB_SIGNAL);

        // Deploy the verifier contract
        vm.startBroadcast();
        VerifierProveRSA65537SHA256 verifierProveRSA65537SHA256 = new VerifierProveRSA65537SHA256();
        vm.stopBroadcast();

        initialVerifiers.push(address(verifierProveRSA65537SHA256));

        return NetworkConfig({
            signatureAlgorithms: initialSignatureAlgorithms,
            verifiers: initialVerifiers,
            nullifiersIndexesInPubSigArray: initialNullifiersIndexesInPubSigArray,
            signers: initialSigners
        });
    }

    function getOrCreateSepoliaConfig() public returns (NetworkConfig memory) {
        vm.startBroadcast();
        VerifierProveRSA65537SHA256 verifierProveRSA65537SHA256 = new VerifierProveRSA65537SHA256();
        VerifierProveRSA65537SHA1 verifierProveRSA65537SHA1 = new VerifierProveRSA65537SHA1();
        VerifierProveRSAPSS65537SHA256 verifierProveRSA65537PSSSHA256 = new VerifierProveRSAPSS65537SHA256();
        vm.stopBroadcast();

        initialSignatureAlgorithms.push(SIGNATURE_ALGORITHM_RSA_65537_SHA256);
        initialSignatureAlgorithms.push(SIGNATURE_ALGORITHM_RSA_65537_SHA1);
        initialSignatureAlgorithms.push(SIGNATURE_ALGORITHM_RSA_PSS_65537_SHA256);

        initialVerifiers.push(address(verifierProveRSA65537SHA256));
        initialVerifiers.push(address(verifierProveRSA65537SHA1));
        initialVerifiers.push(address(verifierProveRSA65537PSSSHA256));

        initialNullifiersIndexesInPubSigArray.push(NULLIFIER_INDEX_IN_PUB_SIGNAL);
        initialNullifiersIndexesInPubSigArray.push(NULLIFIER_INDEX_IN_PUB_SIGNAL);
        initialNullifiersIndexesInPubSigArray.push(NULLIFIER_INDEX_IN_PUB_SIGNAL);

        address INITIAL_SIGNER = vm.envAddress("INITIAL_SIGNER");
        initialSigners.push(INITIAL_SIGNER);

        return NetworkConfig({
            signatureAlgorithms: initialSignatureAlgorithms,
            verifiers: initialVerifiers,
            nullifiersIndexesInPubSigArray: initialNullifiersIndexesInPubSigArray,
            signers: initialSigners
        });
    }
}
