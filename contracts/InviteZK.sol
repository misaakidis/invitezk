// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./MerkleVerifier.sol";

contract InviteZK is Verifier {
    /// @notice Emitted when a leaf is successfully verified and stored
    /// @param verifier Address of the user who verified the leaf
    /// @param root Merkle root associated with the leaf
    /// @param leafHash Hash of the verified leaf
    event LeafVerified(address indexed verifier, bytes32 indexed root, bytes32 leafHash);

    /// @dev Mapping of verified leaves by root (root => leafHash => bool)
    mapping(bytes32 => mapping(bytes32 => bool)) public verifiedLeaves;

    /**
     * @notice Verifies a proof and stores the leaf hash under its corresponding root if valid
     * @param proof The proof struct containing proof data: a, b, and c
     * @param input Public inputs including the root (input[0..7]) and the leaf (input[8..15])
     */
    function verifyAndStoreLeaf(Proof calldata proof, uint256[] calldata input) external {
        require(input.length == 16, "Invalid input length");

        // Extract the root from the input
        bytes32 root = _hashInput(input, 0, 8);

        // Extract the leaf from the input
        bytes32 leafHash = _hashInput(input, 8, 16);

        // Ensure the leaf hasn't already been verified for this root
        require(!verifiedLeaves[root][leafHash], "Leaf already verified for this root");

        // Verify the proof
        uint256 verificationResult = verify(input, proof);
        require(verificationResult == 0, "Invalid proof");

        // Store the verified leaf under the root
        verifiedLeaves[root][leafHash] = true;

        // Emit an event for the verified leaf
        emit LeafVerified(msg.sender, root, leafHash);
    }

    /**
     * @notice Checks if a leaf is verified under a specific root
     * @param root The Merkle root
     * @param leaf The leaf represented as an array of 8 uint256 values
     * @return True if the leaf is verified under the given root, otherwise false
     */
    function isLeafVerified(bytes32 root, uint256[8] calldata leaf) external view returns (bool) {
        bytes32 leafHash = keccak256(abi.encodePacked(leaf));
        return verifiedLeaves[root][leafHash];
    }

    /**
     * @dev Internal helper to hash a subset of the input array
     * @param input The input array
     * @param start The starting index (inclusive)
     * @param end The ending index (exclusive)
     * @return A keccak256 hash of the subset
     */
    function _hashInput(uint256[] calldata input, uint256 start, uint256 end) internal pure returns (bytes32) {
        bytes memory data;
        for (uint256 i = start; i < end; i++) {
            data = abi.encodePacked(data, input[i]);
        }
        return keccak256(data);
    }
}
