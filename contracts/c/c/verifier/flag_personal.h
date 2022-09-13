#ifndef CKB_FLAG_PERSONAL
#define CKB_FLAG_PERSONAL

#include "../common/injection.h"

int _apply_request_args(void *args, size_t i, mol_seg_t lock_args, mol_seg_t data, int herr)
{
    if (lock_args.ptr[0] != FLAG_REQUEST)
    {
        return ERROR_REQUEST_FLAG;
    }
    int ret = CKB_SUCCESS;
    uint8_t lock_hash[HASH_SIZE];
    lua_State *L = (lua_State *)args;
    CHECK_RET(ckbx_flag2_load_caller_lockhash(lock_args.ptr + 1, lock_args.size - 1, lock_hash));
    CHECK_RET(lua_inject_auth_context(L, lock_hash, "user"));
    CHECK_RET(ckbx_flag2_load_recipient_lockhash(lock_args.ptr + 1, lock_args.size - 1, lock_hash));
    CHECK_RET(lua_inject_auth_context(L, lock_hash, "recipient"));
    CHECK_RET(lua_inject_json_context(L, data.ptr, data.size, "personal"));
    // dumplicate KOC into backup
    lua_getglobal(L, LUA_KOC);
    CHECK_RET(lua_deep_copy_table(L));
    lua_setglobal(L, LUA_KOC_BACKUP);
    lua_pop(L, 1);
    // fetch user request method function
    uint8_t function_call[MAX_FUNCTION_CALL_SIZE] = "";
    CHECK_RET(ckbx_flag2_load_function_call(
        lock_args.ptr + 1, lock_args.size - 1, function_call, MAX_FUNCTION_CALL_SIZE));
    ckb_debug((char *)function_call);
    // call method and complete unchecked
    lua_getglobal(L, LUA_KOC_CHECKER);
    if (luaL_loadstring(L, (char *)function_call) || lua_pcall(L, 0, 0, herr) || lua_pcall(L, 0, 0, herr))
    {
        DEBUG_PRINT(
            "[ERROR] invalid request function call. (cell = %lu, payload = %s)", i, (char *)function_call);
        uint64_t input_ckb, output_ckb;
        CHECK_RET(ckbx_get_parallel_cell_capacity(
            CKB_SOURCE_INPUT, false, CKB_SOURCE_OUTPUT, false, i, &input_ckb, &output_ckb));
        if (input_ckb != output_ckb)
        {
            return ERROR_UNMATCHED_REQUEST_CKB;
        }
        // recover KOC from backup
        lua_getglobal(L, LUA_KOC_BACKUP);
        lua_setglobal(L, LUA_KOC);
    }
    // push partial KOC into unchecked
    lua_getglobal(L, LUA_UNCHECKED);
    if (i != luaL_len(L, -1) + 1)
    {
        return ERROR_UNCONTINUOUS_UNCHECKED;
    }
    lua_getglobal(L, LUA_KOC);
    const char *keys[] = {"user", "personal"};
    CHECK_RET(lua_copy_partial_table(L, keys, 2));
    lua_rawseti(L, -3, i);
    lua_pop(L, 2);
    return CKB_SUCCESS;
}

int _apply_personal_data(void *L, size_t i, mol_seg_t user, mol_seg_t personal, int herr)
{
    char method[MAX_FUNCTION_CALL_SIZE];
    sprintf(method, "return %s[%lu]", LUA_UNCHECKED, i);
    int ret = lua_check_personal_data((lua_State *)L, method, user, personal, herr);
    if (ret != CKB_SUCCESS)
    {
        DEBUG_PRINT("[ERROR] mismatched input/output. (cell = %lu)", i);
        return ret;
    }
    return CKB_SUCCESS;
}

int inject_personal_operation(uint8_t *cache, lua_State *L, int herr)
{
    int ret = CKB_SUCCESS;
    // inject unchecked global table
    lua_newtable(L);
    lua_setglobal(L, LUA_UNCHECKED);
    // inject KOC checker global function
    lua_pushcfunction(L, lua_check_koc);
    lua_setglobal(L, LUA_KOC_CHECKER);
    // set random seed by transaction inputs
    uint64_t seed[2];
    CHECK_RET(ckbx_get_random_seeds(cache, MAX_CACHE_SIZE, (uint8_t *)seed));
    CHECK_RET(lua_inject_random_seeds(L, seed, herr));
    // add ckb_deposit method
    LuaOperation operations[] = {
        {"ckb_deposit", lua_ckb_deposit},
        {"ckb_withdraw", lua_ckb_withdraw}};
    CHECK_RET(lua_inject_operation_context(L, operations, 1));
    return CKB_SUCCESS;
}

int verify_personal_data(uint8_t *cache, lua_State *L, int herr, mol_seg_t script_args, uint8_t code_hash[HASH_SIZE])
{
    int ret = CKB_SUCCESS;
    uint64_t len = MAX_CACHE_SIZE;
    // check flag1
    uint8_t project_id[HASH_SIZE];
    CHECK_RET(ckbx_flag1_load_project_id(script_args.ptr + 1, script_args.size - 1, project_id));
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
            cache, MAX_CACHE_SIZE, CKB_SOURCE_INPUT, project_id, code_hash, &input_global_data, global_driver));
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
        ApplyParams apply = {L, herr, _apply_request_args};
        CHECK_RET(ckbx_apply_lock_args_by_code_hash(
            cache, MAX_CACHE_SIZE, CKB_SOURCE_INPUT, code_hash, &apply));
        // first cell from tx-outputs must be Global Cell as well
        mol_seg_t output_global_data;
        CHECK_RET(ckbx_check_global_exist(
            cache, MAX_CACHE_SIZE, CKB_SOURCE_OUTPUT, project_id, code_hash, &output_global_data, global_driver));
        mol_seg_t output_global_driver = {global_driver, HASH_SIZE};
        // check input/output global data
        char checker[MAX_FUNCTION_CALL_SIZE];
        sprintf(checker, "return {driver = %s.driver, global = %s.global}", LUA_KOC, LUA_KOC);
        CHECK_RET(lua_check_global_data(L, checker, output_global_driver, output_global_data, herr));
        // check other outputs personal data
        apply.call = _apply_personal_data;
        CHECK_RET(ckbx_apply_personal_output_by_code_hash(
            cache, MAX_CACHE_SIZE, 1, code_hash, &apply));
    }
    // personal/global data request mode
    else
    {
        ckb_debug("personal/request mode");
        mol_seg_t request_seg;
        CHECK_RET(ckbx_check_request_exist(cache, MAX_CACHE_SIZE, CKB_SOURCE_GROUP_OUTPUT, 0, &request_seg));
        uint8_t caller_hash[HASH_SIZE];
        CHECK_RET(ckbx_flag2_load_caller_lockhash(request_seg.ptr + 1, request_seg.size - 1, caller_hash));
        len = HASH_SIZE;
        ckb_load_cell_by_field(cache, &len, 0, 0, CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK_HASH);
        if (memcmp(cache, caller_hash, HASH_SIZE))
        {
            return ERROR_REQUEST_CALLER_HASH;
        }
    }
    return CKB_SUCCESS;
}

#endif