use ckb_testtool::ckb_crypto::secp::{Generator, Privkey};
use ckb_testtool::ckb_hash::{blake2b_256, new_blake2b};
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::TransactionView,
    packed::{self, *},
    prelude::*,
    H256,
};

#[allow(dead_code)]
pub const MAX_CYCLES: u64 = 100_000_000;

#[allow(dead_code)]
pub fn blake160(data: &[u8]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    let hash = blake2b_256(data);
    buf.clone_from_slice(&hash[..20]);
    buf
}

#[allow(dead_code)]
pub fn gen_keypair() -> (Privkey, [u8; 20]) {
    let keypair = Generator::random_keypair();
    let compressed_pubkey = keypair.1.serialize();
    let script_args = blake160(compressed_pubkey.to_vec().as_slice());
    let privkey = keypair.0;
    (privkey, script_args)
}

#[allow(dead_code)]
pub fn sign_tx(
    tx: TransactionView,
    key: &Privkey,
    extra_witnesses: Vec<WitnessArgs>,
) -> TransactionView {
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = Vec::new();
    let mut blake2b = new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx_hash.raw_data());
    // digest the first witness
    let witness = WitnessArgs::default();
    let zero_lock: Bytes = {
        let mut buf = Vec::new();
        buf.resize(65, 0);
        buf.into()
    };
    let witness_for_digest = witness
        .clone()
        .as_builder()
        .lock(Some(zero_lock).pack())
        .build();
    let witness_len = witness_for_digest.as_bytes().len() as u64;
    blake2b.update(&witness_len.to_le_bytes());
    blake2b.update(&witness_for_digest.as_bytes());
    for witness in &extra_witnesses {
        let witness_len = witness.as_bytes().len() as u64;
        blake2b.update(&witness_len.to_le_bytes());
        blake2b.update(&witness.as_bytes());
    }
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    let sig = key.sign_recoverable(&message).expect("sign");
    signed_witnesses.push(
        witness
            .as_builder()
            .lock(Some(Bytes::from(sig.serialize())).pack())
            .build()
            .as_bytes()
            .pack(),
    );
    for witness in &extra_witnesses {
        signed_witnesses.push(witness.as_bytes().pack());
        // println!("witness = {}", hex::encode(witness.as_bytes()));
    }
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}
