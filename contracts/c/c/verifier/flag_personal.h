#ifndef CKB_FLAG_PERSONAL
#define CKB_FLAG_PERSONAL

#include "utility/callback.h"
#include "utility/injection.h"

int inject_personal_operation(uint8_t *cache, lua_State *L, int herr)
{
    int ret = CKB_SUCCESS;
    // set unchecked global table
    lua_newtable(L);
    lua_setglobal(L, LUA_UNCHECKED);
    // set input/output global offset
    lua_pushinteger(L, 1);
    lua_setglobal(L, LUA_INPUT_OFFSET);
    lua_pushinteger(L, 1);
    lua_setglobal(L, LUA_OUTPUT_OFFSET);
    // set random seed by transaction inputs
    uint64_t seed[2];
    CHECK_RET(ckbx_get_random_seeds(cache, MAX_CACHE_SIZE, (uint8_t *)seed));
    CHECK_RET(lua_inject_random_seeds(L, seed, herr));
    // add ckb_deposit method
    LuaOperation operations[] = {
        {"ckb_deposit", lua_ckb_deposit},
        {"ckb_withdraw", lua_ckb_withdraw}};
    CHECK_RET(lua_inject_operation_context(L, operations, 2));
    return CKB_SUCCESS;
}

int verify_personal_data(
    uint8_t *cache, lua_State *L, int herr, mol_seg_t flag_seg, uint8_t code_hash[HASH_SIZE])
{
    int ret = CKB_SUCCESS;
    uint64_t len = MAX_CACHE_SIZE;
    // check flag1
    uint8_t project_id[HASH_SIZE];
    CHECK_RET(ckbx_identity_load_project_id(flag_seg.ptr, flag_seg.size, project_id));
    // check wether inputs contain same script
    bool is_update_mode;
    CHECK_RET(ckbx_check_personal_update_mode(cache, len, code_hash, &is_update_mode));
    // personal data update mode
    if (is_update_mode)
    {
        ckb_debug("personal/update mode");
        // update mode must have project deployment cell as celldeps
        size_t index;
        CHECK_RET(ckbx_check_project_exist(CKB_SOURCE_CELL_DEP, project_id, &index));
        if (index == (size_t)-1)
        {
            return ERROR_NO_DEPLOYMENT_CELL;
        }
        // first cell from tx-inputs must be Global Cell
        mol_seg_t input_global_data;
        uint8_t global_driver[HASH_SIZE];
        CHECK_RET(ckbx_check_global_exist(
            cache, MAX_CACHE_SIZE, CKB_SOURCE_INPUT, code_hash, project_id, &input_global_data, global_driver));
        CHECK_RET(lua_inject_json_context(L, input_global_data.ptr, input_global_data.size, "global"));
        CHECK_RET(lua_inject_auth_context(L, global_driver, "driver"));
        // get lua code
        len = MAX_CACHE_SIZE;
        CHECK_RET(ckb_load_cell_data(cache, &len, 0, index, CKB_SOURCE_CELL_DEP));
        // load lua code into lua_vm
        CHECK_RET(lua_load_project_code(L, cache, len, herr));
        // inject owner hash
        uint8_t owner_hash[HASH_SIZE];
        len = HASH_SIZE;
        ckb_load_cell_by_field(
            owner_hash, &len, 0, index, CKB_SOURCE_CELL_DEP, CKB_CELL_FIELD_LOCK_HASH);
        CHECK_RET(lua_inject_auth_context(L, owner_hash, "owner"));
        // apply each of requests
        LuaParams lua = {L, project_id, code_hash};
        ApplyParams apply = {&lua, herr, util_apply_request_args};
        CHECK_RET(ckbx_apply_lock_args_by_code_hash(
            cache, MAX_CACHE_SIZE, CKB_SOURCE_INPUT, code_hash, project_id, &apply));
        // first cell from tx-outputs must be Global Cell as well
        mol_seg_t output_global_data;
        CHECK_RET(ckbx_check_global_exist(
            cache, MAX_CACHE_SIZE, CKB_SOURCE_OUTPUT, code_hash, project_id, &output_global_data, global_driver));
        mol_seg_t output_global_driver = {global_driver, HASH_SIZE};
        // check input/output global data
        char checker[MAX_FUNCTION_CALL_SIZE];
        sprintf(checker, "return {driver = %s.driver, global = %s.global}", LUA_KOC, LUA_KOC);
        CHECK_RET(lua_check_global_data(L, checker, output_global_driver, output_global_data, herr));
        // check other outputs personal data
        apply.args = L;
        apply.call = util_apply_personal_data;
        CHECK_RET(ckbx_apply_personal_output_by_code_hash(
            cache, MAX_CACHE_SIZE, 1, code_hash, project_id, &apply));
    }
    // personal/global data request mode
    else
    {
        ckb_debug("personal/request mode");
        mol_seg_t request_seg;
        CHECK_RET(ckbx_check_request_exist(
            cache, MAX_CACHE_SIZE, CKB_SOURCE_GROUP_OUTPUT, 0, code_hash, project_id, &request_seg));
        // check validation of inputs cells
        mol_seg_t cells_seg;
        CHECK_RET(ckbx_request_load_cells(request_seg.ptr, request_seg.size, &cells_seg));
        CHECK_RET(ckbx_check_request_cells_validation(
            cache + request_seg.size, MAX_CACHE_SIZE - request_seg.size, cells_seg, code_hash, project_id));
        // check validation of function celldeps
        size_t count = 0;
        uint8_t celldep_datahashes[HASH_SIZE][MAX_CELLDEP_COUNT];
        CHECK_RET(ckbx_request_load_function_celldeps(
            request_seg.ptr, request_seg.size, celldep_datahashes, &count));
        for (size_t i = 0; i < count; ++i)
        {
            CHECK_RET(ckbx_check_function_celldep_exist(
                cache, MAX_CACHE_SIZE, code_hash, project_id, celldep_datahashes[i], NULL));
        }
    }
    return CKB_SUCCESS;
}

#endif