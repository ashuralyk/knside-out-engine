use super::{
    helper::{sign_tx, blake160, MAX_CYCLES, gen_witnesses_and_signatures},
    protocol,
    *,
};
use ckb_system_scripts::BUNDLED_CELL;
use ckb_testtool::{
    builtin::ALWAYS_SUCCESS,
    context::Context
};
use ckb_tool::{
    ckb_crypto::secp::{Generator, Privkey},
    ckb_hash::blake2b_256,
    ckb_types::{
        bytes::Bytes,
        core::{TransactionBuilder, Capacity},
        packed::{CellDep, CellOutput, CellInput, Script},
        prelude::*,
    },
};

fn get_keypair() -> (Privkey, [u8; 20]) {
    let keypair = Generator::random_keypair();
    let compressed_pubkey = keypair.1.serialize();
    let script_args = blake160(compressed_pubkey.to_vec().as_slice());
    let privkey = keypair.0;
    (privkey, script_args)
}

fn get_nfts(count: u8) -> Vec<[u8; 20]> {
    let mut nfts = vec![];
    for i in 0..count {
        nfts.push(blake160(&i.to_be_bytes()));
    }
    return nfts;
}

fn get_round(user_type: u8, lua_code: Vec<&str>) -> Bytes {
    let user_round = protocol::round(user_type, lua_code);
    Bytes::from(protocol::to_vec(&user_round))
}

#[test]
fn test_success_origin_to_challenge() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("kabletop");
    let out_point = context.deploy_cell(contract_bin);
    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin.to_vec().into());
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_data_out_point)
        .build();
	let luacode = "
		function surrender(prefix)
			print(prefix .. 'surrender the game')
		end
	".as_bytes();
	let luacode_out_point = context.deploy_cell(luacode.into());
	let luacode_dep = CellDep::new_builder()
		.out_point(luacode_out_point)
		.build();

    // generate two users' privkey and pubkhash
    let (user1_privkey, user1_pkhash) = get_keypair();
    let (user2_privkey, user2_pkhash) = get_keypair();

    // prepare scripts
    let lock_args_molecule = (500u64, 5u8, 1024u64, blake2b_256([1]), user1_pkhash, get_nfts(5), user2_pkhash, get_nfts(5));
    let lock_args = protocol::lock_args(lock_args_molecule, vec![blake2b_256(luacode)]);

    let lock_script = context
        .build_script(&out_point, Bytes::from(protocol::to_vec(&lock_args)))
        .expect("script");
    let lock_script_dep = CellDep::new_builder()
        .out_point(out_point)
        .build();

	let mut input_data = vec![];
	// uncomment to test challenge to challenge case
    let witnesses = vec![
        (&user2_privkey, get_round(1u8, vec!["
			print('用户1的回合：')
			print('1.抽牌')
			print('2.回合结束')
		"])),
        (&user1_privkey, get_round(2u8, vec!["
			print('用户2的回合：')
			print('1.抽牌')
			print('2.放置一张牌，跳过回合')
			print('3.回合结束')
		"])),
        (&user2_privkey, get_round(1u8, vec!["
			print('用户1的回合：')
			print('abc123abc123abc123abc123abc123abc123abc123abc123')
			print('2.回合结束')
		"])),
        (&user1_privkey, get_round(2u8, vec!["
			print('用户2的回合：')
			surrender('1.')
			print('2.回合结束')
		"]))
    ];
	let rounds = witnesses
		.iter()
		.map(|(_, round)| round.clone())
		.collect::<Vec<Bytes>>();
    let (_, signatures) = gen_witnesses_and_signatures(&lock_script, 2000u64, witnesses);
	let snapshot = rounds
		.into_iter()
		.enumerate()
		.map(|(i, round)| (round, signatures[i]))
		.collect::<Vec<_>>();
    let challenge = protocol::challenge(2, 1, snapshot, vec![]);
	input_data = protocol::to_vec(&challenge);
	// uncomment to here

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(2000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::from(input_data.clone()),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let output = CellOutput::new_builder()
        .capacity(2000u64.pack())
        .lock(lock_script.clone())
        .build();
	let mut outputs = vec![output];

    // prepare witnesses
    let end_round = protocol::round(1u8, vec![
        "print('user2 draw one card, and skip current round.')",
        // "_winner = 1"
    ]);
    let end_round_bytes = Bytes::from(protocol::to_vec(&end_round));
    let witnesses = vec![
        (&user2_privkey, get_round(1u8, vec!["
			print('用户1的回合：')
			print('1.抽牌')
			print('2.回合结束')
		"])),
        (&user1_privkey, get_round(2u8, vec!["
			print('用户2的回合：')
			print('1.抽牌')
			print('2.放置一张牌，跳过回合')
			print('3.回合结束')
		"])),
        (&user2_privkey, get_round(1u8, vec!["
			print('用户1的回合：')
			print('abc123abc123abc123abc123abc123abc123abc123abc123')
			print('2.回合结束')
		"])),
        (&user1_privkey, get_round(2u8, vec!["
			print('用户2的回合：')
			surrender('1.')
			print('2.回合结束')
		"]))
    ];
	let rounds = witnesses
		.iter()
		.map(|(_, round)| round.clone())
		.collect::<Vec<Bytes>>();
    let (witnesses, signatures) = gen_witnesses_and_signatures(&lock_script, 2000u64, witnesses);
	assert!(rounds.len() == signatures.len());
	let snapshot = rounds
		.into_iter()
		.enumerate()
		.map(|(i, round)| (round, signatures[i]))
		.collect::<Vec<_>>();
    let challenge = protocol::challenge(1, 2, snapshot, vec!["print('user2 draw one card, and skip current round.')"]);
    let mut outputs_data = vec![Bytes::from(protocol::to_vec(&challenge))];

	// uncomment to test from challenge to challenge
	let payback_lock = Script::new_builder()
		.code_hash(blake2b_256([1]).pack())
		.args(Bytes::from(user2_pkhash.to_vec()).pack())
		.build();
	let payback_output = CellOutput::new_builder()
		.capacity(Capacity::bytes(input_data.len()).unwrap().pack())
		.lock(payback_lock)
		.build();
	outputs.push(payback_output);
	outputs_data.push(Bytes::default());
	// uncomment to here

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .cell_dep(secp256k1_data_dep)
		.cell_dep(luacode_dep)
        .build();
    let tx = context.complete_tx(tx);
    let tx = sign_tx(tx, &user1_privkey, witnesses);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass test_success_origin_to_challenge");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_success_origin_to_settlement() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("kabletop");
    let out_point = context.deploy_cell(contract_bin);
    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin.to_vec().into());
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_data_out_point)
        .build();
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point.clone())
        .build();

    // generate two users' privkey and pubkhash
    let (user1_privkey, user1_pkhash) = get_keypair();
    let (user2_privkey, user2_pkhash) = get_keypair();

    // prepare scripts
    let code_hash: [u8; 32] = blake2b_256(ALWAYS_SUCCESS.to_vec());
    let lock_args_molecule = (500u64, 5u8, 1024u64, code_hash, user1_pkhash, get_nfts(5), user2_pkhash, get_nfts(5));
    let lock_args = protocol::lock_args(lock_args_molecule, vec![]);

    let lock_script = context
        .build_script(&out_point, Bytes::from(protocol::to_vec(&lock_args)))
        .expect("lock_script");
    let lock_script_dep = CellDep::new_builder()
        .out_point(out_point)
        .build();
    let user1_always_success_script = context
        .build_script(&always_success_out_point, Bytes::from(user1_pkhash.to_vec()))
        .expect("user1 always_success_script");
    let user2_always_success_script = context
        .build_script(&always_success_out_point, Bytes::from(user2_pkhash.to_vec()))
        .expect("user2 always_success_script");

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(2000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(1500.pack())
            .lock(user1_always_success_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500.pack())
            .lock(user2_always_success_script.clone())
            .build()
    ];

    // prepare witnesses
    let end_round = protocol::round(2u8, vec![
        "ckb.debug('user2 draw one card, and surrender the game.')",
        "_winner = 1"
    ]);
    let end_round_bytes = Bytes::from(protocol::to_vec(&end_round));
    let witnesses = vec![
        (&user2_privkey, get_round(1u8, vec!["ckb.debug('user1 draw one card, and spell it adding HP.')"])),
        (&user1_privkey, get_round(2u8, vec!["ckb.debug('user2 draw one card, and spell it to damage user1.')"])),
        (&user2_privkey, get_round(1u8, vec!["ckb.debug('user1 draw one card, and use it to kill user2.')"])),
        (&user1_privkey, get_round(2u8, vec!["ckb.debug('user2 draw one card, and put it onto battleground.')"])),
        (&user2_privkey, get_round(1u8, vec!["ckb.debug('user1 draw one card, and use it to kill user2.')"])),
        (&user1_privkey, end_round_bytes),
    ];
    let (witnesses, _) = gen_witnesses_and_signatures(&lock_script, 2000u64, witnesses);
    let outputs_data = vec![Bytes::new(), Bytes::new()];

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .cell_dep(secp256k1_data_dep)
        .cell_dep(always_success_script_dep)
        .build();
    let tx = context.complete_tx(tx);
    let tx = sign_tx(tx, &user1_privkey, witnesses);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass test_success_origin_to_settlement");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_success_timeout_to_settlement() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("kabletop");
    let out_point = context.deploy_cell(contract_bin);
    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin.to_vec().into());
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_data_out_point)
        .build();
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point.clone())
        .build();

    // generate two users' privkey and pubkhash
    let (user1_privkey, user1_pkhash) = get_keypair();
    let (user2_privkey, user2_pkhash) = get_keypair();

    // prepare scripts
    let code_hash: [u8; 32] = blake2b_256(ALWAYS_SUCCESS.to_vec());
    let lock_args_molecule = (500u64, 5u8, 10000u64, code_hash.clone(), user1_pkhash, get_nfts(5), user2_pkhash, get_nfts(5));
    let lock_args = protocol::lock_args(lock_args_molecule, vec![]);

    let lock_script = context
        .build_script(&out_point, Bytes::from(protocol::to_vec(&lock_args)))
        .expect("lock_script");
    let lock_script_dep = CellDep::new_builder()
        .out_point(out_point)
        .build();
    let user1_always_success_script = context
        .build_script(&always_success_out_point, Bytes::from(user1_pkhash.to_vec()))
        .expect("user1 always_success_script");
    let user2_always_success_script = context
        .build_script(&always_success_out_point, Bytes::from(user2_pkhash.to_vec()))
        .expect("user2 always_success_script");

    // prepare witnesses
    let end_round = protocol::round(2u8, vec![
        "ckb.debug('user2 draw one card, and quit the game without responding.')",
        // "_winner = 1"
    ]);
    let end_round_bytes = Bytes::from(protocol::to_vec(&end_round));
    let witnesses = vec![
        (&user2_privkey, get_round(1u8, vec!["ckb.debug('user1 draw one card, and spell it adding HP.')"])),
        (&user1_privkey, get_round(2u8, vec!["ckb.debug('user2 draw one card, and spell it to damage user1.')"])),
        (&user2_privkey, get_round(1u8, vec!["ckb.debug('user1 draw one card, and use it to kill user2.')"])),
        (&user1_privkey, get_round(2u8, vec!["ckb.debug('user2 draw one card, and put it onto battleground.')"])),
        (&user2_privkey, get_round(1u8, vec!["ckb.debug('user1 draw one card, and use it to kill user2.')"])),
        (&user1_privkey, end_round_bytes),
    ];
	let rounds = witnesses
		.iter()
		.map(|(_, round)| round.clone())
		.collect::<Vec<Bytes>>();
    let (witnesses, signatures) = gen_witnesses_and_signatures(&lock_script, 2000u64, witnesses);
	assert!(rounds.len() == signatures.len());
	let snapshot = rounds
		.into_iter()
		.enumerate()
		.map(|(i, round)| (round, signatures[i]))
		.collect::<Vec<_>>();
    let challenge = protocol::challenge(1, 1, snapshot, vec![]);
	let challenge_data = protocol::to_vec(&challenge);
	let extra_ckb = Capacity::bytes(challenge_data.len()).unwrap().as_u64();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(2000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::from(challenge_data),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .since(11036u64.pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity((1500 + extra_ckb).pack())
            .lock(user1_always_success_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500.pack())
            .lock(user2_always_success_script.clone())
            .build()
    ];
    let outputs_data = vec![Bytes::new(), Bytes::new()];

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .cell_dep(secp256k1_data_dep)
        .cell_dep(always_success_script_dep)
        .build();
    let tx = context.complete_tx(tx);
    let tx = sign_tx(tx, &user1_privkey, witnesses);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass test_success_timeout_to_settlement");
    println!("consume cycles: {}", cycles);
}
