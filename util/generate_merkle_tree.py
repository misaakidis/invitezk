import hashlib
import random
import json

def sha256(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def generate_merkle_tree(leaves):
    # Ensure the leaves count is a power of 2 (16 leaves for a depth 4 tree)
    assert len(leaves) == 16, "Merkle tree must have 16 leaves"
    
    # Compute Merkle tree levels from leaves to root
    tree = leaves
    while len(tree) > 1:
        tree = [sha256(tree[i] + tree[i + 1]) for i in range(0, len(tree), 2)]
    return tree[0]  # The root is the only element left in the tree

def generate_test_case():
    # Generate 16 random leaf hashes
    leaves = [sha256(str(random.randint(0, 100000))) for _ in range(16)]
    
    # Generate Merkle root from leaves
    root = generate_merkle_tree(leaves)
    
    # Create a JSON structure for the Solidity test
    test_case = {
        "proof": {
            "a": ["0x" + sha256("proof_a"), "0x" + sha256("proof_a")],
            "b": [
                ["0x" + sha256("proof_b_1"), "0x" + sha256("proof_b_2")],
                ["0x" + sha256("proof_b_3"), "0x" + sha256("proof_b_4")]
            ],
            "c": ["0x" + sha256("proof_c"), "0x" + sha256("proof_c")]
        },
        "input": leaves + [root]  # First 16 elements are leaves, the last is the root
    }

    return json.dumps(test_case, indent=4)

if __name__ == "__main__":
    # Generate the test case
    test_case = generate_test_case()
    
    # Print the generated test case
    print("Generated Merkle Tree Test Case:")
    print(test_case)
