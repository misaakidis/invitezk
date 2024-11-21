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
}
    