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
        vk.alpha = Pairing.G1Point(uint256(0x21fe1313969d69bfc317123265b46ac00f0a8e05edc5176c525d6bca26c82359), uint256(0x25dc2c25a567242f7dc6c0b495ada2328ec4b954c75f10529f37c392d1536aa7));
        vk.beta = Pairing.G2Point([uint256(0x16782c4abd18fb48979d65a8fb0d56711800e5ee3298df6112897ad11909cb85), uint256(0x00125ffe810853a0504b4ba19f8e5785672f136b282f9009cfe06eabb5a86a59)], [uint256(0x07312862ceedc187194b44c04ed91e24cffb9c1b892d2dc7261fdcdc40a749b7), uint256(0x240f416d9ceb5e48397d4607c711870cee9e79d3b27041ae2a45b9c113c00846)]);
        vk.gamma = Pairing.G2Point([uint256(0x2ee0269007172a1381ad7415ad21d86082bf38a03a69987b44c09a00c22ffe0d), uint256(0x1e287ff6b4c304b82b66e57e0596997b3d292d6f6256b903279b66855b6eb86b)], [uint256(0x189955b434ffceb98161472e83d8d82d70236b4f7a8e72b6bcd48d167726068d), uint256(0x15d42c00cfdd5b3b517f64ca22fbad17affafc142046b7bdc3a0a1c5a17cf287)]);
        vk.delta = Pairing.G2Point([uint256(0x1be753872de8c798ab612d4f31dcb1a5b7c0eab91b3dbcfd202231fa58795e92), uint256(0x1cb3126204e285e92db4a501381b8118d54b34e7864c23eed553ec33155a759b)], [uint256(0x0e7dcc9b523140dee7671512a8203f79bb7d079e1102f9f80575bde28f7916f4), uint256(0x2a13c56c713531cf5b2f8b1741c1fef19b70eb1efa934e14e1c7e1ddb7eef2e3)]);
        vk.gamma_abc = new Pairing.G1Point[](10);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x291b4f95b6d77a3156098851b59198a3f354022a56a54708354cbcf171ab64f1), uint256(0x014b894ffe60f9bf869ffe4c28e64dab6390acc578f7596803b97e7b96d6968f));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2af123933ed0a810d2d44272f71637c8c505f51dd36a1bb07354eb69b12431dd), uint256(0x033d5ba4b89543a4dbf6205eae1f2dc532586754471aa62de34f18383eea0618));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0e934f25b075a1ce250c988ff88b57f98e1bd532b456fc75b3e68c730a3f8a85), uint256(0x15b34e73a0fd998071f28ae3d3dd8910c7a1e592a7a55f595514ad1fc83a48ab));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x26cadbbc4b8d34ac237f4cfea824d4e37ccfd83a82f1194238dd4cde8f3dfa81), uint256(0x1f2e794c81c60277606fa7e7c07f667c30d6472ff4748cd0b6c286307afbbd72));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x27d6e0a893458188d7c6eda482bfe8fc9acdb25f785c00a7f8e3d66df45a3c08), uint256(0x0c9e7108ed4ab8446f8b61092aa19b2a99f4cd8897e41c5510a5c463bca52c77));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2ee4e603d4c209533c2341e0360aab50584aeffdd0126b8b79535b1f3eb95bcb), uint256(0x223758e3090d8cd3e8e6d2faa8d285bfb500c4a5b95101c3cda58989c5b47990));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x169896ec4c869203e3289f0a7bda3a3c7e3865b2b001ab25b693738936bababd), uint256(0x15d64557e56348730b51c4cf8b2f1f0a575b7ce403e7c37d81a03b24406714df));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x12a603885d470a4ff0d071bced15a33ad9b1c60e4bb4c778f18dc1dc9c935fe7), uint256(0x1b5c6b86433fddcb30c795638171bcc16d96638e71a71cef0354f7f2a850b24c));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1a2cfb05b305a2f7313f83925df0a32e4c55c9b091c4a1b9cfee3c1903cb3291), uint256(0x2d6d577f0aae04ef562b585182d30568aa8f4760269928e0a22f759f4899bb3a));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x10714a86de2402ec855173990d5601e2be43104430962d6af2ae6e727aada9f1), uint256(0x18f6a8b6e17fd6245a82be366ec710bcafc6a37abe8b1864a09832eec1cf3b91));
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
            Proof memory proof, uint[9] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](9);
        
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
