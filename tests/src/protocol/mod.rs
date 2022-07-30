#![allow(dead_code)]

#[allow(clippy::all)]
mod protocol;

use molecule::prelude::{Builder, Byte, Entity};

fn mol_hash(v: &[u8; 32]) -> protocol::Hash {
    let mut mol_bytes: [Byte; 32] = [Byte::default(); 32];
    for i in 0..32 {
        mol_bytes[i] = Byte::from(v[i]);
    }
    protocol::Hash::new_builder().set(mol_bytes).build()
}

fn mol_string(v: &[u8]) -> protocol::String {
    let bytes = v
        .to_vec()
        .iter()
        .map(|byte| Byte::new(*byte))
        .collect::<Vec<Byte>>();
    protocol::String::new_builder().set(bytes).build()
}

fn mol_string_opt(v: Option<&[u8]>) -> protocol::StringOpt {
    if let Some(v) = v {
        let string = mol_string(v);
        protocol::StringOpt::new_builder().set(Some(string)).build()
    } else {
        protocol::StringOpt::new_builder().set(None).build()
    }
}

fn mol_project_info(
    name: &str,
    author: &str,
    website: &str,
    description: &str,
) -> protocol::ProjectInfo {
    protocol::ProjectInfo::new_builder()
        .name(mol_string(name.as_bytes()))
        .author(mol_string(author.as_bytes()))
        .website(mol_string(website.as_bytes()))
        .description(mol_string(description.as_bytes()))
        .build()
}

pub fn mol_deployment(lua_code: &str) -> protocol::Deployment {
    let project_info = mol_project_info("", "", "", "");
    protocol::Deployment::new_builder()
        .code(mol_string(lua_code.as_bytes()))
        .project(project_info)
        .build()
}

pub fn mol_flag_0(hash: &[u8; 32]) -> Vec<u8> {
    let mut flag_0_bytes = protocol::Flag0::new_builder()
        .project_id(mol_hash(hash))
        .build()
        .as_bytes()
        .to_vec();
    flag_0_bytes.insert(0, 0u8);
    flag_0_bytes
}

pub fn mol_flag_1(hash: &[u8; 32]) -> Vec<u8> {
    let mut flag_1_bytes = protocol::Flag1::new_builder()
        .project_id(mol_hash(hash))
        .build()
        .as_bytes()
        .to_vec();
    flag_1_bytes.insert(0, 1u8);
    flag_1_bytes
}

pub fn mol_flag_2(hash: &[u8; 32], method: &str, lockscript: &[u8], recipient: Option<&[u8]>) -> Vec<u8> {
    let mut flag_2_bytes = protocol::Flag2::new_builder()
        .project_id(mol_hash(hash))
        .function_call(mol_string(method.as_bytes()))
        .caller_lockscript(mol_string(lockscript))
        .recipient_lockscript(mol_string_opt(recipient))
        .build()
        .as_bytes()
        .to_vec();
    flag_2_bytes.insert(0, 2u8);
    flag_2_bytes
}
