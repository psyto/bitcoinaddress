extern crate bitcoin_hashes;
extern crate hex;
extern crate secp256k1;

use bitcoin_hashes::{ripemd160, sha256, Hash};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::str;

fn main() {
    // 1. Having a private ECDSA key
    // 18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725
    let secp = Secp256k1::new();
    let h1 = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725".as_bytes();
    let secret_key = SecretKey::from_slice(&hex::decode(h1).unwrap())
        .ok()
        .unwrap();
    // 2. Take the corresponding public key generated with it (33 bytes, 1 byte 0x02 (y-coord is even), and 32 bytes corresponding to X coordinate)
    // 0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    // 3. Perform SHA-256 hashing on the public key
    // 0b7c28c9b7290c98d7438e70b3d3f7c848fbd7d1dc194ff83f4f7cc9b1378e98
    let h3 = sha256::Hash::hash(&public_key.serialize());
    // 4. Perform RIPEMD-160 hashing on the result of SHA-256
    // f54a5851e9372b87810a8e60cdd2e7cfd80b6e31
    let h4 = ripemd160::Hash::hash(&h3).into_inner();
    // 5. Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
    // 00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31
    let mut h5 = [0u8; 1].to_vec();
    h5.extend(&h4);
    // 6. Perform SHA-256 hash on the extended RIPEMD-160 result
    // ad3c854da227c7e99c4abfad4ea41d71311160df2e415e713318c70d67c6b41c
    let h6 = sha256::Hash::hash(&h5);
    // 7. Perform SHA-256 hash on the result of the previous SHA-256 hash
    // c7f18fe8fcbed6396741e58ad259b5cb16b7fd7f041904147ba1dcffabf747fd
    let h7 = sha256::Hash::hash(&h6);
    // 8. Take the first 4 bytes of the second SHA-256 hash. This is the address checksum
    // c7f18fe8
    let h8 = &h7[..4];
    // 9. Add the 4 checksum bytes from stage 7 at the end of extended RIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.
    // 00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8
    let mut h9 = h5.clone();
    h9.extend(h8);
    // 10. Convert the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format
    // 1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs
    let h10 = bs58::encode(&h9).into_string();

    println!("h1: {:?}", str::from_utf8(h1).unwrap());
    println!("h2: {:?}", public_key);
    println!("h3: {:?}", &hex::encode(&h3));
    println!("h4: {:?}", &hex::encode(&h4));
    println!("h5: {:?}", &hex::encode(&h5));
    println!("h6: {:?}", &hex::encode(&h6));
    println!("h7: {:?}", &hex::encode(&h7));
    println!("h8: {:?}", &hex::encode(&h8));
    println!("h9: {:?}", &hex::encode(&h9));
    println!("h10: {:?}", &h10);
}
