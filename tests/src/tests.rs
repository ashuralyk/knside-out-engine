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
    let func_init_global: mlua::Function = lua.globals().get("InitGlobal").expect("get InitGlobal");
    let global_data = func_init_global
        .call::<_, mlua::Table>(())
        .expect("call InitGlobal");
    let global_data_json = serde_json::to_string(&global_data).unwrap();
    println!("global_json = {}", global_data_json);
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
