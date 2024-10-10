# Proof of Passport Register

Smart contract designed to store and verify proofs of passport. This contract allows for the registration of recipients after validating provided proofs, management of signers and verifiers, and validation of proofs.
This contract was developed based on the circuits implementation of [OpenPassport](https://github.com/zk-passport/openpassport)

This project uses the [Foundry framework](https://github.com/foundry-rs/foundry) for testing and deployment.

## Table of Contents

- [About](#about)
- [Getting Started](#getting-started)
  - [Requirements](#requirements)
  - [Quickstart](#quickstart)
- [Usage](#usage)
  - [Start a Local Node](#start-a-local-node)
  - [Deploy](#deploy)
  - [Deploy to Other Networks](#deploy-to-other-networks)
- [Testing](#testing)
  - [Test Coverage](#test-coverage)
- [Interactions](#interactions)
- [Estimate Gas](#estimate-gas)
- [Formatting](#formatting)
- [Static Analysis](#static-analysis)
- [License](#license)
- [Author](#author)

## About

The Proof of Passport Register contract is designed to store and verify proofs of passport. It allows registered signers to register recipients after validating proofs. The contract also supports adding and removing signers and verifiers, as well as validating proofs.

## Getting Started

### Requirements

- Git: [Download](https://git-scm.com/downloads)
  -  Verify installation: ```git --version```
- Foundry: [Installation Guide](https://book.getfoundry.sh/getting-started/installation)
  - Verify installation: ```forge --version```

### Quickstart

Clone the repository and build the project:

```bash
git clone https://github.com/yourusername/proof-of-passport-register
cd proof-of-passport-register
forge build
```

## Usage

### Start a Local Node
Start a local Ethereum node for testing using Anvil (included with Foundry):

```bash
anvil
```

### Deploy
In a separate terminal, deploy the contract to your local node:

```bash
forge script script/DeployProofOfPassportRegister.s.sol:DeployProofOfPassportRegister --fork-url http://localhost:8545 --broadcast
```

### Deploy to Other Networks
To deploy to networks like Sepolia or Mainnet, specify the network in the deploy script and provide the necessary RPC URLs and private keys.

Example for Sepolia:
```bash
forge script script/Deploy.s.sol:DeployProofOfPassportRegister --rpc-url $SEPOLIA_RPC_URL --private-key $PRIVATE_KEY --broadcast --verify
```

### Setup Environment Variables
Create a ```.env``` file and set the following variables:
- ```PRIVATE_KEY```: Your private key (ensure it is for a test account). Alternatively you can use ```cast``` to store your account securely and use it for deployment.
- ```SEPOLIA_RPC_URL``` or ```MAINNET_RPC_URL```: RPC URL for the network.
- ```ETHERSCAN_API_KEY```(optional): For contract verification.

## Testing
Run the tests using:

```bash
forge test
```

### Test Coverage
Generate a test coverage report:

```bash
forge coverage
```

## Interactions
Interact with the deployed contract using ```cast``` commands.

Examples:

- Check if an address is a signer
```bash
cast call <contract_address> "checkIfAddressIsSigner(address)(bool)" <signer_address> --rpc-url $RPC_URL
```
- Register a recipient with proof:
```bash
cast send <contract_address> "registerWithProof((uint256[2],uint256[2][2],uint256[2],uint256[45]),address)" <proof> <recipient_address> --private-key $PRIVATE_KEY --rpc-url $RPC_URL
```

## Estimate Gas
Estimate gas usage:
```bash
forge snapshot
```

## Formatting
Ensure code is formatted correctly:

```bash
forge fmt
```

## Static Analysis
Run [Slither](https://github.com/crytic/slither) for static analysis:

```bash
slither .
```
## License
This project is licensed under the MIT License.

## Author
Developed by JustaLab.

---

**Note**: For detailed implementation and advanced usage, please refer to the contract's source code and documentation.

---

Thank you for your interest in the Proof of Passport Register contract. If you have any questions or need assistance, feel free to reach out.

Happy coding!


