// SPDX-License-Identifier: GPL-3.0
        
pragma solidity >=0.4.22 <0.9.0;

import "remix_tests.sol"; 
import "remix_accounts.sol";

import "../contracts/InviteZK.sol";
import "../contracts/MerkleVerifier.sol";

contract testSuite {
    InviteZK inviteZK;

    /// 'beforeAll' runs before all other tests
    /// More special functions are: 'beforeEach', 'beforeAll', 'afterEach' & 'afterAll'
    function beforeAll() public {
        // <instantiate contract>
        inviteZK = new InviteZK();
        Assert.ok(address(inviteZK) != address(0), "InviteZK contract should be deployed");
    }

    /// Tests invalid proof rejection
    function testInvalidProof() public {
        // Prepare an invalid proof
        Verifier.Proof memory invalidProof = Verifier.Proof(
            Pairing.G1Point(uint256(0x000), uint256(0x000)), // proof.a
            Pairing.G2Point( // proof.b
                [uint256(0x000), uint256(0x000)],
                [uint256(0x000), uint256(0x000)]
            ),
            Pairing.G1Point(uint256(0x000), uint256(0x000))  // proof.c
        );

        uint256[] memory input = new uint256[](16);
        input[0] = 12345; input[1] = 67890; input[2] = 11111; input[3] = 22222;
        input[4] = 33333; input[5] = 44444; input[6] = 55555; input[7] = 66666;
        input[8] = 77777; input[9] = 88888; input[10] = 99999; input[11] = 10101;
        input[12] = 12121; input[13] = 14141; input[14] = 16161; input[15] = 18181;

        // Attempt verification with an invalid proof and expect it to fail
        try inviteZK.verifyAndStoreLeaf(invalidProof, input) {
            Assert.ok(false, "Expected verification to fail for an invalid proof");
        } catch Error(string memory reason) {
            Assert.equal(reason, "Invalid proof", "Error message does not match the expected 'Invalid proof'");
        }
    }

        /// @notice Tests valid proof and leaf verification
    function testValidProof() public {
        // Proof values from the JSON
        InviteZK.Proof memory proof = Verifier.Proof(
            Pairing.G1Point(
                uint256(0x5ba320c4ba7788e9ea56bafdb70be0c452ba2581a0181750e66802efdac9c2e4),
                uint256(0x5ba320c4ba7788e9ea56bafdb70be0c452ba2581a0181750e66802efdac9c2e4)
            ), // proof.a
            Pairing.G2Point( // proof.b
                [
                    uint256(0xec308144c75b683fa19ef7d7ece27758e4a320b4ac7fbdf2af2b446f72545cc0),
                    uint256(0x77c8eb686bcf56ef882d320129d5476920647cb66177710e3cad8ef3b75abbf6)
                ],
                [
                    uint256(0xc3d37bc6c708d961dd86bca725cbe4737225f72d06531279e077a1a218d17053),
                    uint256(0xe0ba66ba15eb4b078cc79eb18fe7a4ff20e5f4aa49564f772a7d78e8cbf696e2)
                ]
            ),
            Pairing.G1Point(
                uint256(0x544b4160466254c4391d376d87e4d305671d66173ea32f5333f419f66adf39e2),
                uint256(0x544b4160466254c4391d376d87e4d305671d66173ea32f5333f419f66adf39e2)
            ) // proof.c
        );

        // Input data from the provided JSON (first 16 elements are leaves, the last is the root)
        uint256[] memory input = new uint256[](16);
        input[0] = 0x04ae09a9f90464204cd501bb916adb75c509585e44f62c174a399f6c9b593538;
        input[1] = 0xad7c2b601d56bacae7e4dcd1d4e0598f151162a05137498551f94584fd5ebd75;
        input[2] = 0xa1a57315af0421443e73ff39f4cc4afaabfb05e5c435fafd3504fd91ab223453;
        input[3] = 0xfe29298ce75de3d0619cdb1a6d412f013bc1cd1e3390bf8d9a3de24f6fa38704;
        input[4] = 0x0f4121d0ef1df4c86854c7ebb47ae1c93de8aec8f944035eeaa6495dd71a0678;
        input[5] = 0x8eeb87c7f7cabe51fa0cdab0a7fef46ca972e417c3c65c536301a4526905fb03;
        input[6] = 0xe053531c86e793f0e596664ffbbb84d9059bf55eec514331ae6414e8def32cab;
        input[7] = 0xa44a5172f9daad1ad8466c425ef2044f0eda1dabac3e631494b1aa76b42dcf2a;
        input[8] = 0xacff539c0d5cd0d34613b4233b7b4bb86cea4d1c505d509eb7bb2c7b54380746;
        input[9] = 0x54168c674354adf3e75823fef2cc416f4506a128ce0d7310ed02fa74cf4a353b;
        input[10] = 0x220415ba00c300be926ebc663201ead0f5189245bb38580b3cc7b3fb7e6faaf2;
        input[11] = 0xdc6da118e41e69e54d9b834807d8c05b7e2a511ea7930fd44cfb6e9102247309;
        input[12] = 0x053c0393073e7a0cf89672ba131217d385904e523333a1d4f024df3b7373c91a;
        input[13] = 0x962ecf83db2637527ca1d36ed4673b233bce0779ecac2a6ff0ed72a7096c1485;
        input[14] = 0xe9af75782f0d99d9832f674b2c4b73f9ec579fe8e786c89edac9b43388e009cc;
        input[15] = 0xcfb56cd190cca8911942562852c1368619d7c825a86f764fda3e9bbd2f90d6f5;

        // Extract the Merkle root from the input
        bytes32 root = keccak256(abi.encodePacked(
            input[0], input[1], input[2], input[3],
            input[4], input[5], input[6], input[7]
        ));

        // Verify and store the leaf using the proof and input
        inviteZK.verifyAndStoreLeaf(proof, input);

        // Verify the leaf is stored correctly under the root
        uint256[8] memory leaf = [
            uint256(input[8]), uint256(input[9]), uint256(input[10]), uint256(input[11]),
            uint256(input[12]), uint256(input[13]), uint256(input[14]), uint256(input[15])
        ];
        Assert.ok(inviteZK.isLeafVerified(root, leaf), "Leaf should be verified");
    }
}
    