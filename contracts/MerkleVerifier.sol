// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x1242610795601d7f505fe94deffc38733d4e76959b740cd5993c5cc5ef00878b), uint256(0x0f97d0856fbfcef4c9635cb63e3d33ea327c3396078f4dd54c2811ddb087bd48));
        vk.beta = Pairing.G2Point([uint256(0x039acbcb15b334409151c2afed5f65d0eb0d6da80ef0c8b7fd8fe4ff151e4714), uint256(0x0c90d5c3db976b9708f96822f3a31dfd3c7dde0471f8d5801969257e1f5b7828)], [uint256(0x0415bd01b96d70c47075b9a51dc6326b2b3a2f6c785b210da742b2aeb995c9c6), uint256(0x2f3771707982653e5df29769bdfd58fe52f0ed616c3e7878ef70a7c1ecb6f59e)]);
        vk.gamma = Pairing.G2Point([uint256(0x1b04164e837b816d46379042e6113c9350c32a86326d88bf545cb2ed9ddadf76), uint256(0x16bb5a920d6f6c28bc2ba966c84b2fd36b539ab6a7ec0fc360689c0cf67d42b4)], [uint256(0x1c0b0abd53f90be704484fac3760e698497e16d49506b1c1ae8ea43a0584de6a), uint256(0x13714561dd4d0e7a6131ed63fd830fd1af722538b4374ca4ec36f2d2ff64958b)]);
        vk.delta = Pairing.G2Point([uint256(0x0c1c861587ae462b103241a084ee7247d7a00a70e92c9e11a8fd8d58b9c93aa6), uint256(0x2fa2b64628247a9303307124bd8acafc993ecf2ba8ed95d2591f06ed756f03be)], [uint256(0x06b58f97492c06ff4a8c4941381b6a7e1166f76e2100ac802a8535a5b751cf8b), uint256(0x033094b1d2a2ea852f795dc9737508cd21a6090522db453ee632f00ed4cf19f7)]);
        vk.gamma_abc = new Pairing.G1Point[](18);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0da3f7636f400a0945f9df32b62316745f632e2901257ede180cb739a4231642), uint256(0x2c7aad7264beb308ef8add21f8d7add0d18316a6c5f193a401d21b42d2b5f429));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1e2372c635da43e8ecba93728f2845a35441e5280c42dfb8daa93480db045508), uint256(0x10ad861075886820ec64f412a7010f81dfc0ddf74a91efa5043f96092cde4258));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x28745ae2e83775bb8ade96d00729121c0846386bc30fa30c6206036e851f48a7), uint256(0x253867f5c34668e5de97f18240983dc1393b3c24d3037e51f451033f8998bdb2));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2880872fcafca4c099935c12bb78b7026b9a46415fe6dafbd79a36b0c48a1830), uint256(0x013cb33123d2d56e6bd77cc49fdb57b4038e50c5dae4a31f5261d2c5ebc49bed));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1a7ad5f4bad6ca1a07aaaeb000638928d17ad37a75b944ad2a6f3ce864f2786c), uint256(0x29fc196ffed27b293d3a10bcf686de5e776a9135d9dd74d1eb6667ae578a2b62));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0ba0a08854c69e776a45c742427181b4153561641d56019ca6db5f73121be0f5), uint256(0x2c2132a878324e4779258e1746226cb971bd87d0417222e54958ae72d5e07faf));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x284bedc1caba62da61efe2ec5a923d7c1b07f8f1939f4c2b01ca5ba5da2bcc79), uint256(0x033eeabdfd6437ccffdba83e41bf8d57a095f2d973a80cb22f3ae6f1a9d5690d));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x15157395513238f814b7be326eff31dc3c1c66a0345cb7063a1017cc3d24e0fb), uint256(0x0b527896723598817739efaa41c000ce36ab315edca4f9112afa4619ad595474));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2e8b1557e328f6297028343746ef69bc84808e33a253c19c2408172e0a9f7064), uint256(0x14da05c053b9e9070f2de12905eb47c7cca79ec9e99802d2de766574b8babca4));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x08166225476cac8d72f25a61b9e3784b535f3592cb21a30791cd4d83c0993f41), uint256(0x2afc295122125edc339a57f4d4fda6658ea768294ebf42d81d010dbba9e34a69));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2c74e9938d9662a9eb03f4d9376e29d70f4c3ef03fead7a7524c100c421f2c13), uint256(0x23b82603cd4bbc2e36a2fd9b3a6eb5464011f768bb7c1d24ab9aa23de0f704ae));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x20591e8d04b6cfcd89c78cb26285d666af6415639680d513ecb105ae72c3b9e2), uint256(0x010b3ed7bd87bd3685e47a06354ed0c347904cd902807bc30b0cd64f5b12a46b));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2945511095c11929def4c880f7df1b4f0dbfc846128c5280f4522314d959da4b), uint256(0x2e16cdf74fe01337e3c5ef5594b220c866bc562a26547de803a392a2c2340784));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2a75258e5f55a7ed866d97e47a350d125b21ef1ca6e505f9caba2cb7c2e79020), uint256(0x0fe3b387b6e67e546a210e560749012e8917d7044013660605ab0b7af161abaa));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0b316d0a4fca90057a11832a8152b945d37e01167bc57c282a8f6671cffe26c4), uint256(0x015c43bef49046c5c95a5b07206121564736d5344fcbbd54685d8cb261870589));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1a5d8a6bd352399d3d2d2805c39bda84588b341e55703ae8256c27de7299fa7c), uint256(0x2abfbf3a28ca2f14b045544cde883cfef1dfa1c20f9b08125999f42b6fb62f17));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0e67f4f212b854200d1c3b8ce8e09808c936c573c512c9fdf72de4a48e0ad1e9), uint256(0x022c8669344cacb92a3952040ee4858868c69f16271dc0ae06de785a62028062));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2e188014b65defc1a642d9724f4ac015b6f43244dddb2dd51eeb1b5ca03b5b6c), uint256(0x2b6a5efe400c997b49d22e6a1c71043a7da2ecaf5de864eaa584d78cf2f578b9));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[17] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](17);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
