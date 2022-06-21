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
