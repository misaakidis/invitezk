// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./MerkleVerifier.sol";

contract InviteZK is Verifier {
    // Event to log successful verifications
    event LeafVerified(address indexed verifier, uint256[8] leaf);

    // Store verified leaves
    mapping(bytes32 => bool) public verifiedLeaves;

    /**
     * @dev Verifies the proof and stores the leaf hash if valid.
     * @param proof The proof struct containing a, b, and c values.
     * @param input Public inputs including the root and leaf.
     *              input[0..7] is the root.
     *              input[8..15] is the leaf.
     */
    function verifyAndStoreLeaf(
        Proof memory proof,
        uint256[] memory input
    ) public {
        // Ensure the input length is correct for depth 3 Merkle tree (8 for root, 8 for leaf)
        require(input.length == 16, "Invalid input length");

        // Extract the leaf from the public inputs (second 8 values in the input array)
        uint256[8] memory leaf;
        for (uint256 i = 0; i < 8; i++) {
            leaf[i] = input[i + 8];
        }

        // Hash the leaf array into a single value
        bytes32 leafHash = keccak256(abi.encodePacked(leaf));

        // Ensure the leaf hasn't already been verified
        require(!verifiedLeaves[leafHash], "Leaf already verified");

        // Call the `verify` function
        uint256 verificationResult = verify(input, proof);
        require(verificationResult == 0, "Invalid proof");

        // Store the verified leaf
        verifiedLeaves[leafHash] = true;

        // Emit an event for the verified leaf
        emit LeafVerified(msg.sender, leaf);
    }

    /**
     * @dev Checks if a leaf has been verified.
     * @param leaf The leaf represented as an array of 8 uint256 values.
     * @return True if the leaf is verified, otherwise false.
     */
    function isLeafVerified(uint256[8] memory leaf) public view returns (bool) {
        bytes32 leafHash = keccak256(abi.encodePacked(leaf));
        return verifiedLeaves[leafHash];
    }
}