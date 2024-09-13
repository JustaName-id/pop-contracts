// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MerkleTree Registry Contract
 * @notice This contract is used to store the Merkle Root of the supported public keys' Merkle Tree
 */
contract MerkleTreeRegistry is Ownable {
    uint256 s_merkleRoot;

    error MerkleTreeRegistry__SameRoot();

    constructor(uint256 merkleRoot) Ownable(msg.sender) {
        s_merkleRoot = merkleRoot;
    }

    function setRoot(uint256 merkleRoot) public onlyOwner {
        if (s_merkleRoot == merkleRoot) {
            revert MerkleTreeRegistry__SameRoot();
        }

        s_merkleRoot = merkleRoot;
    }

    function checkRoot(uint256 merkleRoot) public view returns (bool) {
        return s_merkleRoot == merkleRoot;
    }

    /**
     * Getter Functions
     */
    function getRoot() public view returns (uint256) {
        return s_merkleRoot;
    }
}
