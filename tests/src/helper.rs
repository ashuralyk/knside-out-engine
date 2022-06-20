use ckb_tool::ckb_crypto::secp::Privkey;
use ckb_tool::ckb_hash::{blake2b_256, new_blake2b};
use ckb_tool::ckb_types::{
    bytes::Bytes,
    core::TransactionView,
    packed::{self, *},
    prelude::*,
    H256,
};
use std::convert::TryInto;

#[allow(dead_code)]
pub const CODE_HASH_SECP256K1_BLAKE160: [u8; 32] = [
    155, 215, 224, 111, 62, 207, 75, 224, 242, 252, 210, 24, 139, 35, 241, 185, 252, 200, 142, 93,
    75, 101, 168, 99, 123, 23, 114, 59, 189, 163, 204, 232,
];

#[allow(dead_code)]
pub const MAX_CYCLES: u64 = 100_000_000;

#[allow(dead_code)]
pub const TYPE: u8 = 1;

#[allow(dead_code)]
const SIGNATURE_SIZE: usize = 65;

#[allow(dead_code)]
pub fn blake160(data: &[u8]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    let hash = blake2b_256(data);
    buf.clone_from_slice(&hash[..20]);
    buf
}

#[allow(dead_code)]
pub fn gen_witnesses_and_signatures(
	script: &Script, ckb: u64, raw_witness: Vec<(&Privkey, Bytes)>
) -> (Vec<WitnessArgs>, Vec<[u8; 65]>) {
    let mut message = [0u8; 32];
    let mut witnesses = vec![];
    let mut signature = vec![];
	let mut all_signatures = vec![];
    for i in 0..raw_witness.len() {
        let (privk, code) = &raw_witness[i];
        let mut blake2b = new_blake2b();
        if i == 0 {
            blake2b.update(&script.calc_script_hash().raw_data());
            // blake2b.update(&ckb.to_le_bytes());
        } else {
            blake2b.update(&message);
            blake2b.update(&signature);
        }
        // println!("round{} = {}, count = {}", i, hex::encode(&code), code.len());
        blake2b.update(&code);
        blake2b.finalize(&mut message);
        let digest = H256::from(message);
        let sig = privk.sign_recoverable(&digest).expect("sign");
        witnesses.push(WitnessArgs::new_builder()
            .lock(Some(Bytes::from(sig.serialize())).pack())
            .input_type(Some(code.clone()).pack())
            .build());
        signature = sig.serialize();
		all_signatures.push(signature.clone().try_into().unwrap());
    }
	witnesses[0] = witnesses[0]
		.clone()
		.as_builder()
		.output_type(Some(Bytes::from(blake2b_256([1]).to_vec())).pack())
		.build();
    (witnesses, all_signatures)
}

#[allow(dead_code)]
pub fn sign_tx(tx: TransactionView, key: &Privkey, extra_witnesses: Vec<WitnessArgs>) -> TransactionView {
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = Vec::new();
    let mut blake2b = new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx_hash.raw_data());
    // digest the first witness
    let witness = WitnessArgs::default();
    let zero_lock: Bytes = {
        let mut buf = Vec::new();
        buf.resize(SIGNATURE_SIZE, 0);
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
