#ifndef CKB_FLAG_GLOBAL
#define CKB_FLAG_GLOBAL

#include "../common/header.h"
#include "../common/lua_wrap.h"
#include "../common/high_level.h"

int verify_global_data(uint8_t *cache, lua_State *L, int herr, mol_seg_t script_args, uint8_t code_hash[HASH_SIZE])
{
    int ret = CKB_SUCCESS;
    // check flag0
    uint8_t project_id[HASH_SIZE];
    CHECK_RET(ckbx_flag0_load_project_id(script_args.ptr + 1, script_args.size - 1, project_id));
    // check cell mode
    bool is_update_mode;
    CHECK_RET(ckbx_check_global_update_mode(cache, MAX_CACHE_SIZE, &is_update_mode));
    // global data update mode
    if (is_update_mode)
    {
        ckb_debug("global/update mode");
        size_t index;
        CHECK_RET(ckbx_check_project_exist(CKB_SOURCE_CELL_DEP, project_id, &index));
        if (index == (size_t)-1)
        {
            return ERROR_NO_DEPLOYMENT_CELL;
        }
        CHECK_RET(ckbx_check_request_exist(cache, MAX_CACHE_SIZE, CKB_SOURCE_INPUT, 1, NULL));
    }
    // global data initial mode
    else
    {
        ckb_debug("global/initial mode");
        size_t index;
        CHECK_RET(ckbx_check_project_exist(CKB_SOURCE_OUTPUT, project_id, &index));
        if (index == (size_t)-1)
        {
            return ERROR_NO_DEPLOYMENT_CELL;
        }
        // inject `owner` into KOC context
        uint64_t len = HASH_SIZE;
        uint8_t owner_lockhash[HASH_SIZE];
        CHECK_RET(ckb_load_cell_by_field(
            owner_lockhash, &len, 0, index, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH));
        CHECK_RET(lua_inject_auth_context(L, owner_lockhash, "owner"));
        // load lua code
        len = MAX_CACHE_SIZE;
        CHECK_RET(ckb_load_cell_data(cache, &len, 0, index, CKB_SOURCE_OUTPUT));
        // push lua code into lua_vm
        CHECK_RET(lua_load_project_code(L, cache, len, herr));
        // load global json data
        mol_seg_t global_json = {cache, MAX_CACHE_SIZE};
        CHECK_RET(ckb_load_cell_data(
            global_json.ptr, (uint64_t *)&global_json.size, 0, 0, CKB_SOURCE_GROUP_OUTPUT));
        // load global driver lock_hash and inject into KOC context
        uint8_t driver_lockhash[HASH_SIZE];
        mol_seg_t global_driver = {driver_lockhash, HASH_SIZE};
        CHECK_RET(ckb_load_cell_by_field(
            global_driver.ptr, (uint64_t *)&global_driver.size, 0, 0, CKB_SOURCE_GROUP_OUTPUT, CKB_CELL_FIELD_LOCK_HASH));
        CHECK_RET(lua_inject_auth_context(L, driver_lockhash, "driver"));
        // check global data format
        CHECK_RET(lua_check_global_data(L, "return construct()", global_driver, global_json, herr));
    }
    return CKB_SUCCESS;
}

#endif