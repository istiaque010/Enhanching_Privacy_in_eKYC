# Enhancing Privacy in eKYC 


### Information preprocessing:


```python 
import hashlib
import struct

# Function to convert a string into 32-bit chunks
def string_to_chunks(data):
    # Convert each character to its ASCII value
    ascii_values = [ord(char) for char in data]
    
    # Pad the ASCII values with zeros to make the total length a multiple of 4
    while len(ascii_values) % 4 != 0:
        ascii_values.append(0)
    
    # Pack every 4 ASCII values into a 32-bit chunk
    chunks = [struct.unpack(">I", bytes(ascii_values[i:i+4]))[0] for i in range(0, len(ascii_values), 4)]
    
    return chunks

# Dynamically input eKYC information
fields = {
    "Full Name": input("Enter Full Name: "),
    "Date of Birth": input("Enter Date of Birth (YYYY-MM-DD): "),
    "Gender": input("Enter Gender: "),
    "Nationality": input("Enter Nationality: "),
    "National ID Number": input("Enter National ID Number: "),
    "Address": input("Enter Address: "),
    "Issue Date": input("Enter Issue Date (YYYY-MM-DD): "),
    "Expiry Date": input("Enter Expiry Date (YYYY-MM-DD): "),
    "Place of Birth": input("Enter Place of Birth: "),
    "Issuing Authority": input("Enter Issuing Authority: ")
}

# Selective Disclosure: Ask the user which fields to include
print("\nSelect which fields to include in the hash computation:")
selected_fields = []
selected_info = {}
for key in fields:
    include = input(f"Include {key}? (y/n): ").strip().lower()
    if include == 'y':
        selected_fields.append(fields[key])
        selected_info[key] = fields[key]

# Combine selected fields into a single string
ekyc_combined = ''.join(selected_fields)

# Print the selected eKYC information (keys only)
print("\n--- Selected eKYC Information ---")
for key in selected_info.keys():
    print(f"{key}")

# Convert the combined string to 32-bit chunks
ekyc_info_chunks = string_to_chunks(ekyc_combined)

# Ensure we have exactly 16 chunks (padded if necessary)
while len(ekyc_info_chunks) < 16:
    ekyc_info_chunks.append(0)

print("\n--- eKYC Info (16 x 32-bit chunks) ---")
for chunk in ekyc_info_chunks:
    print(f"0x{chunk:08x}")

# Convert the 32-bit chunks to bytes
ekyc_info_bytes = b''.join([struct.pack('>I', chunk) for chunk in ekyc_info_chunks])

# Compute the SHA-256 hash
hash_value = hashlib.sha256(ekyc_info_bytes).hexdigest()

# Convert the hash into 8 chunks of 32 bits
hash_chunks = [int(hash_value[i:i+8], 16) for i in range(0, len(hash_value), 8)]

print("\n--- Expected Hash (8 x 32-bit integers) ---")
for chunk in hash_chunks:
    print(f"0x{chunk:08x}")

```
### Information preprocessing Output:

![image](https://github.com/user-attachments/assets/9432f6fb-14ab-4757-ab18-33f95e19032b)

![image](https://github.com/user-attachments/assets/083d96f8-a2b8-4d62-a793-6614b75f96a2)

### Smart contract to generate proof:
```solidity 
import "hashes/sha256/512bit" as sha256;

// The main function for proving eKYC information
def main() -> bool {
   
    
    // Padding the remaining chunks with zeros to fill the 512-bit requirement
    u32[16] eKYC_info = [
        0x4a6f686e, 0x4d616c65, 0x4a617061, 0x34002e00, 0x6e000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
    ];
    u32[8] expected_hash = [
        0x726dd5a5, 0xabc4f8a7, 0xc38b6b54, 0x5ef62227,
        0x2fc076ea, 0xa7250548, 0x949c546f, 0x31a8a816
    ];
    u32[8] computed_hash = sha256(eKYC_info[0..8], eKYC_info[8..16]);
    bool isValid = computed_hash == expected_hash;
    return isValid;
}
```
### Output Smart contract to generated proof:

```json
{
  "scheme": "g16",
  "curve": "bn128",
  "proof": {
    "a": [
      "0x2e7a04074ba02d252a724e540ef02ff5decc482b663d81b13a00e050808507f4",
      "0x156dfb587c8f1d1e4f2d46ba2c2ce1893fa7822c2b177711db659b6e6b416a5a"
    ],
    "b": [
      [
        "0x197c97d411c1ce2b91edea269003169a145c230290e82acd83c75b0474f5e39d",
        "0x01daedbabb99e6699e821c41bb8d8936ffe2dbcc72a70839d45aed1b7f691915"
      ],
      [
        "0x195bfa6da102cbfd8ac64a60fb13c1e71d45bd5f9ae1ff6dc375ce6f934b7f5e",
        "0x2bb4af9b8614cb800ac99d3bf71bf72ce4b2885ef7d6be1b5ee5e91597844e0e"
      ]
    ],
    "c": [
      "0x1ab79954eaf6e22920c589740c2dc069135dcaccd8fe84ee37ca45b22400a768",
      "0x1ca433afdad808eb04e456a33ab15276895abbf693c2dfd276f77857d8d36195"
    ]
  },
  "inputs": [
    "0x0000000000000000000000000000000000000000000000000000000000000000"
  ]
}
```

### Verification Smart contract in on-chain:
```solidity
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
        vk.alpha = Pairing.G1Point(uint256(0x1291e415a576b5c72976a77ec9dd46008b9e6c8b7f4d487b12aad3f0c6b54bee), uint256(0x0d025f5a1308e84d0e4f5096eef23d8f088513c2c6ec8491a714fdaaa5eb8855));
        vk.beta = Pairing.G2Point([uint256(0x189a4e7847a96adb6d2dc168f9a4d25f3e4176b2ffa7b702f26e22e5dff8fd77), uint256(0x07ffbb2db5de2add45e6218e78b009ca5c8c29291e57aa7c7fd4c6a6867b3417)], [uint256(0x1d14d7114e65fb84ab41b5b8bef12c21e6aa5f5ce128fe9ce21128f0841d13ad), uint256(0x066ea610f9443208022415bbd95588460fe21295e78797d0b28bdc7c77ba11de)]);
        vk.gamma = Pairing.G2Point([uint256(0x2dbea1748bc5152a32186c788abb4c4dd309ecde285c73d1d6c3c67ebf4afbb4), uint256(0x181e148066ebcd4e919eb9ce76056bd54ebf10cce6d84fcef79ca7bad1de85e7)], [uint256(0x2d59a9cbb493aa74226984328f4bbf04ade487721d20f123b023038794f37ab6), uint256(0x0fa7005755dd07f5edf191d8aca191c94c769d1644208744a8f0b5b2aebf3af9)]);
        vk.delta = Pairing.G2Point([uint256(0x2946cc803433b50be337f5b9b7b4ca2e48358598c39b915f9f1ce76fd5275599), uint256(0x020de7170a84d7b2cff1712def15f815941f722d714cb661a4389b8482dfde69)], [uint256(0x09220d830139d64bd05903720020bc5520c4540874d3d9ab0bf43356646d4366), uint256(0x27864ae57fda35bbdf041a0357d4a7d3e5da527963cd2e67fe321b10eca170c6)]);
        vk.gamma_abc = new Pairing.G1Point[](2);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x037a7dd5a75647ff449bdb3dc80136481cc53c04159c6c9cf5d11a94eb7047c0), uint256(0x202b7827dfb8a50f1cd547bf69c631b3e2178c49884c7190868d819d2e83e7f1));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x23a5ef83b064fb393db9c67acf6887cd5469233e1eeb69f9053dd0b4ea5fd31b), uint256(0x036c3b8b78a61f67a578fb81c9c47d5898084abf24337de6c40dee6638946b06));
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
            Proof memory proof, uint[1] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](1);
        
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

```

### on-chain verification output:

![image](https://github.com/user-attachments/assets/66260420-e669-4cc0-a564-141453d65ece)

