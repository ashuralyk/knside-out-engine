#![allow(unused)]

use ckb_system_scripts::BUNDLED_CELL;
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_testtool::{
    ckb_hash::blake2b_256,
    ckb_types::{
        bytes::Bytes,
        core::{Capacity, TransactionBuilder},
        packed::{CellDep, CellInput, CellOutput, Script},
        prelude::*,
    },
};
use molecule::prelude::Entity as MolEntity;

use crate::{
    helper::{blake160, gen_keypair, sign_tx, MAX_CYCLES},
    protocol, Loader,
};

#[test]
fn test_success_deploy_project() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin = Loader::default().load_binary("lua-engine");
    let out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point.clone())
        .build();
    let always_success_lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![1]))
        .expect("always_success script");
    let type_id_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![2]))
        .expect("type_id script");

    // build project deployment and flag 0
    let luacode = std::fs::read_to_string("./lua/nft.lua").unwrap();
    let deployment = protocol::mol_deployment(luacode.as_str());
    let flag_0 = protocol::mol_flag_0(&type_id_script.calc_script_hash().unpack());

    // build inside-out type script
    let contract_script = context
        .build_script(&out_point, Bytes::from(flag_0))
        .expect("contract script");
    let contract_dep = CellDep::new_builder().out_point(out_point).build();

    // build normal input
    let input = CellInput::new_builder()
        .previous_output(
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(1000.pack())
                    .lock(always_success_lock_script.clone())
                    .build(),
                Bytes::new(),
            ),
        )
        .build();

    // build project outputs
    let outputs = vec![
        // deployment cell
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(type_id_script).pack())
            .build(),
        // global data cell
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(always_success_lock_script.clone())
            .type_(Some(contract_script).pack())
            .build(),
    ];

    // build outputs data
    let lua = mlua::Lua::new();
    lua.load(&luacode).exec().expect("exec lua code");
    let func_init_global: mlua::Function = lua.globals().get("construct").expect("get construct");
    let global_data = func_init_global
        .call::<_, mlua::Table>(())
        .expect("call construct");
    let global_data_json = serde_json::to_string(&global_data).unwrap();
    let outputs_data = vec![
        Bytes::from(deployment.as_bytes().to_vec()).pack(),
        Bytes::from(global_data_json.as_bytes().to_vec()).pack(),
    ];

    // build tx
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data)
        .cell_dep(always_success_script_dep)
        .cell_dep(contract_dep)
        .build();

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass test_success_deploy_project");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_success_personal_request() {
    let mut context = Context::default();
    let contract_bin = Loader::default().load_binary("lua-engine");
    let out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point.clone())
        .build();
    let always_success_lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![1]))
        .expect("always_success script");
    let type_id_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![2]))
        .expect("type_id script");

    // build project deployment and flag 0 and 2
    let flag_1 = protocol::mol_flag_1(&type_id_script.calc_script_hash().unpack());
    let flag_2 = protocol::mol_flag_2(
        "mint()",
        always_success_lock_script.as_slice(),
        None
    );

    // build inside-out type script and lock script
    let request_script = context
        .build_script(&out_point, Bytes::from(flag_2))
        .expect("request script");
    let contract_script = context
        .build_script(&out_point, Bytes::from(flag_1))
        .expect("personal script");
    let contract_dep = CellDep::new_builder().out_point(out_point).build();

    // build projectt input
    let input = CellInput::new_builder()
        .previous_output(
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(1000.pack())
                    .lock(always_success_lock_script.clone())
                    .build(),
                Bytes::new(),
            ),
        )
        .build();

    // build project outputs
    let outputs = vec![
        // normal cell
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(always_success_lock_script)
            .build(),
        // unlocked normal cell for request 1
        CellOutput::new_builder()
            .capacity(1000.pack())
            .lock(request_script)
            .type_(Some(contract_script).pack())
            .build(),
    ];

    // build project outputs data
    let outputs_data = vec![
        Bytes::new().pack(),
        Bytes::new().pack(),
    ];

    // build tx
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data)
        .cell_dep(always_success_script_dep)
        .cell_dep(contract_dep)
        .build();

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass test_success_personal_request");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_success_update_personal_data() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin = Loader::default().load_binary("lua-engine");
    let out_point = context.deploy_cell(contract_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point.clone())
        .build();
    let always_success_lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![1]))
        .expect("always_success script");
    let type_id_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![2]))
        .expect("type_id script");
    let user1_lock_script = always_success_lock_script.clone();
    let user2_lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![4]))
        .expect("user2 script");

    // build project deployment and flag 0 and 2
    let luacode = std::fs::read_to_string("./lua/nft.lua").unwrap();
    let deployment = protocol::mol_deployment(luacode.as_str());
    let flag_0 = protocol::mol_flag_0(&type_id_script.calc_script_hash().unpack());
    let flag_1 = protocol::mol_flag_1(&type_id_script.calc_script_hash().unpack());
    let flag_2_1 = protocol::mol_flag_2(
        "updateGlobal('max_nft_count', 10)",
        user1_lock_script.as_slice(),
        None
    );
    let flag_2_2 = protocol::mol_flag_2(
        "mint()",
        user2_lock_script.as_slice(),
        None
    );

    // build inside-out type script and lock script
    let contract_script = context
        .build_script(&out_point, Bytes::from(flag_0))
        .expect("contract script");
    let request_1_script = context
        .build_script(&out_point, Bytes::from(flag_2_1))
        .expect("request script");
    let request_2_script = context
        .build_script(&out_point, Bytes::from(flag_2_2))
        .expect("request script");
    let personal_script = context
        .build_script(&out_point, Bytes::from(flag_1))
        .expect("personal script");
    let contract_dep = CellDep::new_builder().out_point(out_point).build();

    // build project cell dep with deployment
    let deployment_dep = CellDep::new_builder()
        .out_point(
            context.create_cell(
                CellOutput::new_builder()
                    .lock(always_success_lock_script.clone())
                    .type_(Some(type_id_script).pack())
                    .build_exact_capacity(Capacity::zero())
                    .unwrap(),
                Bytes::from(deployment.as_bytes().to_vec()),
            ),
        )
        .build();

    // build previous global data input
    let previous_global = "{\"current_token_id\":0,\"burned_nft_count\":0,\"minted_nft_count\":0,\"max_nft_count\":0,\"updated_nft_count\":0,\"loot_project_id\":\"0xabcdefg\",\"transfered_nft_count\":0}";
    let inputs = vec![
        // previous global cell
        CellInput::new_builder()
            .previous_output(
                context.create_cell(
                    CellOutput::new_builder()
                        .capacity(Capacity::bytes(1000).unwrap().pack())
                        .lock(always_success_lock_script.clone())
                        .type_(Some(contract_script.clone()).pack())
                        .build(),
                    Bytes::from_static(previous_global.as_bytes()),
                ),
            )
            .build(),
        // locked personal request cell 1
        CellInput::new_builder()
            .previous_output(
                context.create_cell(
                    CellOutput::new_builder()
                        .capacity(Capacity::bytes(1000).unwrap().pack())
                        .lock(request_1_script)
                        .type_(Some(personal_script.clone()).pack())
                        .build(),
                    Bytes::new(),
                ),
            )
            .build(),
        // locked personal request cell 2
        CellInput::new_builder()
            .previous_output(
                context.create_cell(
                    CellOutput::new_builder()
                        .capacity(Capacity::bytes(1000).unwrap().pack())
                        .lock(request_2_script)
                        .type_(Some(personal_script.clone()).pack())
                        .build(),
                    Bytes::new(),
                ),
            )
            .build(),
    ];

    // build project outputs
    let outputs = vec![
        // next global data cell
        CellOutput::new_builder()
            .capacity(Capacity::bytes(1000).unwrap().pack())
            .lock(always_success_lock_script)
            .type_(Some(contract_script).pack())
            .build(),
        // unlocked normal cell for request 1
        CellOutput::new_builder()
            .capacity(Capacity::bytes(1000).unwrap().pack())
            .lock(user1_lock_script)
            // .type_(Some(personal_script.clone()).pack())
            .build(),
        // unlocked normal cell for request 2
        CellOutput::new_builder()
            .capacity(Capacity::bytes(1000).unwrap().pack())
            .lock(user2_lock_script)
            .type_(Some(personal_script).pack())
            .build(),
    ];

    // build project outputs data
    let next_global = "{\"current_token_id\":1,\"burned_nft_count\":0,\"minted_nft_count\":1,\"max_nft_count\":10,\"updated_nft_count\":0,\"loot_project_id\":\"0xabcdefg\",\"transfered_nft_count\":0}";
    let next_personal = "{\"token_id\":1,\"glossaries\":[]}";
    let outputs_data = vec![
        Bytes::from_static(next_global.as_bytes()).pack(),
        Bytes::new().pack(),
        Bytes::from_static(next_personal.as_bytes()).pack(),
    ];

    // build tx
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data)
        .cell_dep(deployment_dep)
        .cell_dep(always_success_script_dep)
        .cell_dep(contract_dep)
        .build();

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass test_success_update_personal_data");
    println!("consume cycles: {}", cycles);
}
