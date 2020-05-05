extern crate bitcoin_hashes;
extern crate hex;
extern crate secp256k1;

use bitcoin_hashes::{ripemd160, sha256, Hash};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::str;

fn main() {

    // https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    // 1. Having a private ECDSA key.
    // 18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725
    let secp = Secp256k1::new();
    let private_key = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725".as_bytes();
    let secret_key = SecretKey::from_slice(&hex::decode(private_key).unwrap())
        .ok()
        .unwrap();

    // 2. Take the corresponding public key generated with it.
    // (33 bytes, 1 byte 0x02 (y-coord is even), and 32 bytes corresponding to X coordinate)
    // 0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    // 3. Perform SHA-256 hashing on the public key.
    // 0b7c28c9b7290c98d7438e70b3d3f7c848fbd7d1dc194ff83f4f7cc9b1378e98
    let sha256_public_key = sha256::Hash::hash(&public_key.serialize());

    // 4. Perform RIPEMD-160 hashing on the result of SHA-256.
    // f54a5851e9372b87810a8e60cdd2e7cfd80b6e31
    let ripmd160_sha256_public_key = ripemd160::Hash::hash(&sha256_public_key).into_inner();

    // 5. Add version byte in front of RIPEMD-160 hash (0x00 for Main Network).
    // 00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31
    let mut extended_ripmd160_sha256_public_key = [0u8; 1].to_vec();
    extended_ripmd160_sha256_public_key.extend(&ripmd160_sha256_public_key);

    // 6. Perform SHA-256 hash on the extended RIPEMD-160 result.
    // ad3c854da227c7e99c4abfad4ea41d71311160df2e415e713318c70d67c6b41c
    let sha256_extended_ripmd160_sha256_public_key =
        sha256::Hash::hash(&extended_ripmd160_sha256_public_key);

    // 7. Perform SHA-256 hash on the result of the previous SHA-256 hash.
    // c7f18fe8fcbed6396741e58ad259b5cb16b7fd7f041904147ba1dcffabf747fd
    let double_sha256_extended_ripmd160_sha256_public_key =
        sha256::Hash::hash(&sha256_extended_ripmd160_sha256_public_key);

    // 8. Take the first 4 bytes of the second SHA-256 hash.
    // This is the address checksum.
    // c7f18fe8
    let checksum = &double_sha256_extended_ripmd160_sha256_public_key[..4];

    // 9. Add the 4 checksum bytes from stage 7 at the end of extended RIPEMD-160 hash from stage 4.
    // This is the 25-byte binary Bitcoin Address.
    // 00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8
    let mut binary_bitcoin_address = extended_ripmd160_sha256_public_key.clone();
    binary_bitcoin_address.extend(checksum);

    // 10. Convert the result from a byte string into a base58 string using Base58Check encoding.
    // This is the most commonly used Bitcoin Address format
    // 1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs
    let bitcoin_address = bs58::encode(&binary_bitcoin_address).into_string();

    println!("Private Key: {:?}", str::from_utf8(private_key).unwrap());
    println!("Public Key: {:?}", public_key);
    println!("SHA-256 Public Key: {:?}", &sha256_public_key);
    println!(
        "RIPMD-160 SHA-256 Public Key: {:?}",
        &hex::encode(&ripmd160_sha256_public_key)
    );
    println!(
        "Extended RIPMD-160 SHA-256 Public Key: {:?}",
        &hex::encode(&extended_ripmd160_sha256_public_key)
    );
    println!(
        "SHA-256 Extended RIPMD-160 SHA-256 Public Key: {:?}",
        &sha256_extended_ripmd160_sha256_public_key
    );
    println!(
        "Double SHA-256 Extended RIPMD-160 SHA-256 Public Key: {:?}",
        &double_sha256_extended_ripmd160_sha256_public_key
    );
    println!("Chechsum: {:?}", &hex::encode(&checksum));
    println!(
        "25-Byte Binary Bitcoin Address: {:?}",
        &hex::encode(&binary_bitcoin_address)
    );
    println!("Bitcoin Address: {:?}", &bitcoin_address);
}

/*
Private Key: "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725"
Public Key: PublicKey(52235b7e88048aad1d51d886e4533fb53c40a8f11a3ce82f8aae874ad63a8650a62b589c7e18eef2d65e8538dfa111bc3a10167723779efa99a253342470d42c)
SHA-256 Public Key: 0b7c28c9b7290c98d7438e70b3d3f7c848fbd7d1dc194ff83f4f7cc9b1378e98
RIPMD-160 SHA-256 Public Key: "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"
Extended RIPMD-160 SHA-256 Public Key: "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"
SHA-256 Extended RIPMD-160 SHA-256 Public Key: ad3c854da227c7e99c4abfad4ea41d71311160df2e415e713318c70d67c6b41c
Double SHA-256 Extended RIPMD-160 SHA-256 Public Key: c7f18fe8fcbed6396741e58ad259b5cb16b7fd7f041904147ba1dcffabf747fd
Chechsum: "c7f18fe8"
25-Byte Bitcoin Address: "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8"
Bitcoin Address: "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
*/
