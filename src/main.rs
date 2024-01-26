use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, rand_core::RngCore},
    Aes256Gcm
};
use blsttc::SecretKey as SecretKeyBls;
use std::time::Instant;

fn main() {
    bench(100);
    bench(1024);
    bench(1024 * 1024);
}

fn bench(msg_size: usize) {
    // aes gcm
    let iters = 1000;
    let mut ns_encrypting_aes = 0;
    let mut ns_decrypting_aes = 0;
    for _ in 0..iters {
        let key = Aes256Gcm::generate_key(&mut OsRng);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let mut msg = vec![0u8; msg_size];
        OsRng.fill_bytes(&mut msg);
        let now = Instant::now();
        let ct = cipher.encrypt(&nonce, msg.as_ref()).unwrap();
        ns_encrypting_aes += now.elapsed().as_nanos();
        let now = Instant::now();
        cipher.decrypt(&nonce, ct.as_ref()).unwrap();
        ns_decrypting_aes += now.elapsed().as_nanos();
    }
    let ns_per_aes_encryption = ns_encrypting_aes / iters;
    println!("aes encrypt {} bytes: {:?} ns per encryption", msg_size, ns_per_aes_encryption);
    let ns_per_aes_decryption = ns_decrypting_aes / iters;
    println!("aes decrypt {} bytes: {:?} ns per decryption", msg_size, ns_per_aes_decryption);
    // bls
    let mut ns_encrypting_bls = 0;
    let mut ns_decrypting_bls = 0;
    for _ in 0..iters {
        let key = SecretKeyBls::random();
        let mut msg = vec![0u8; msg_size];
        OsRng.fill_bytes(&mut msg);
        let now = Instant::now();
        let ct = key.public_key().encrypt(&msg);
        ns_encrypting_bls += now.elapsed().as_nanos();
        let now = Instant::now();
        key.decrypt(&ct);
        ns_decrypting_bls += now.elapsed().as_nanos();
    }
    let ns_per_bls_encryption = ns_encrypting_bls / iters;
    println!("bls encrypt {} bytes: {:?} ns per encryption", msg_size, ns_per_bls_encryption);
    let ns_per_bls_decryption = ns_decrypting_bls / iters;
    println!("bls decrypt {} bytes: {:?} ns per decryption", msg_size, ns_per_bls_decryption);
    println!("");
}
