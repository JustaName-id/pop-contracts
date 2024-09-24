// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MerkleTree Registry Contract
 * @notice This contract is used to store the Merkle Root of the supported public keys' Merkle Tree
 * @author JustaLab
 */
contract MerkleTreeRegistry is Ownable {
    uint256 private s_merkleRoot;

    error MerkleTreeRegistry__SameRoot();

    event RootUpdated(uint256 indexed newRoot);

    constructor(uint256 merkleRoot) Ownable(msg.sender) {
        s_merkleRoot = merkleRoot;
    }

    /**
     * @notice Set the new Merkle Root
     * @param merkleRoot The new Merkle Root
     */
    function setRoot(uint256 merkleRoot) public onlyOwner {
        if (s_merkleRoot == merkleRoot) {
            revert MerkleTreeRegistry__SameRoot();
        }

        s_merkleRoot = merkleRoot;

        emit RootUpdated(merkleRoot);
    }

    /**
     * @notice Check if the given Merkle Root is the same as the stored Merkle Root
     * @param merkleRoot The Merkle Root to check
     * @return True if the given Merkle Root is the same as the stored Merkle Root
     */
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
