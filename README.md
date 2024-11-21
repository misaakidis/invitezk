# InviteZK

InviteZK is a Solidity smart contract that verifies Merkle tree inclusion proofs using zero-knowledge proofs (zk-SNARKs). The project leverages SNARK-efficient Pedersen hashes for verifying leaves under a Merkle root in a privacy-preserving manner.

InviteZK can be used to manage project whitelists, enabling users to prove their inclusion without exposing the entire list. It also supports private group invitations, such as granting access to Semaphore groups, by verifying membership with zero-knowledge proofs. Additionally, QR-code invitations can include Merkle proofs, allowing secure and private verification for events or services.


## Features

* Verifies Merkle tree inclusion proofs via zk-SNARKs.
* Tracks and stores verified leaves by their respective Merkle roots.
* Prevents duplicate verification of the same leaf for the same root.
* Logs verified leaves along with the root and verifier address.
* Uses SNARK-friendly Pedersen hashes for efficient proof verification.


## License

This project is licensed under the MIT License.