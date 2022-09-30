#ifndef CKB_LUA_INTERNAL
#define CKB_LUA_INTERNAL

#include "../../common/header.h"
#include "../../common/lua_wrap.h"
#include "../../common/high_level.h"

int _inject_personal_celldeps_json_context(
    lua_State *L, uint8_t *cache, size_t len, mol_seg_t request_seg,
    uint8_t code_hash[HASH_SIZE], uint8_t project_id[HASH_SIZE], const char *name)
{
    lua_getglobal(L, LUA_KOC);
    if (!lua_istable(L, -1))
    {
        lua_newtable(L);
    }
    int ret = CKB_SUCCESS;
    size_t count = 0;
    uint8_t lock_hashes[HASH_SIZE][MAX_PERSONAL_DEP_COUNT];
    CHECK_RET(ckbx_flag2_load_personal_celldep_lockhashes(
        request_seg.ptr, request_seg.size, lock_hashes, &count));
    lua_newtable(L);
    for (size_t i = 0; i < count; ++i)
    {
        // key
        lua_pushhexstrng(L, lock_hashes[i], HASH_SIZE);
        // value
        mol_seg_t celldep_data;
        CHECK_RET(ckbx_check_personal_celldep_exist(
            cache, len, code_hash, project_id, lock_hashes[i], &celldep_data));
        CHECK_RET(_json_to_table(
            L, (char *)celldep_data.ptr, celldep_data.size, NULL));
        // personal_deps[key] = value
        lua_settable(L, -2);
    }
    lua_setfield(L, -2, name);
    lua_setglobal(L, LUA_KOC);
    return CKB_SUCCESS;
}

int util_apply_request_args(
    void *args, size_t i, mol_seg_t cache, mol_seg_t lock_args, mol_seg_t data, int herr)
{
    if (lock_args.ptr[0] != FLAG_REQUEST)
    {
        return ERROR_REQUEST_FLAG;
    }
    uint8_t lock_hash[HASH_SIZE];
    LuaParams *params = (LuaParams *)args;
    lua_State *L = (lua_State *)params->L;
    mol_seg_t request_seg = {lock_args.ptr + 1, lock_args.size - 1};
    int ret = CKB_SUCCESS;
    CHECK_RET(ckbx_flag2_load_caller_lockhash(request_seg.ptr, request_seg.size, lock_hash));
    CHECK_RET(lua_inject_auth_context(L, lock_hash, "user"));
    CHECK_RET(ckbx_flag2_load_recipient_lockhash(request_seg.ptr, request_seg.size, lock_hash));
    CHECK_RET(lua_inject_auth_context(L, lock_hash, "recipient"));
    CHECK_RET(lua_inject_stringvec_json_context(L, data, "personals"));
    CHECK_RET(_inject_personal_celldeps_json_context(
        L, cache.ptr, cache.size, request_seg, params->code_hash, params->project_id, "personal_deps"));
    // dumplicate KOC into backup
    lua_getglobal(L, LUA_KOC);
    CHECK_RET(lua_deep_copy_table(L));
    lua_setglobal(L, LUA_KOC_BACKUP);
    lua_pop(L, 1);
    // fetch user request method function
    uint8_t function_call[MAX_FUNCTION_CALL_SIZE] = "";
    CHECK_RET(ckbx_flag2_load_function_call(
        request_seg.ptr, request_seg.size, function_call, MAX_FUNCTION_CALL_SIZE));
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
    const char *keys[] = {"user", "personals"};
    CHECK_RET(lua_flatten_copy_table(L, keys, 2));
    lua_rawseti(L, -3, i);
    lua_pop(L, 2);
    return CKB_SUCCESS;
}

int util_apply_personal_data(
    void *L, size_t i, mol_seg_t cache, mol_seg_t user, mol_seg_t personal, int herr)
{
    snprintf((char *)cache.ptr, cache.size, "return %s[%lu]", LUA_UNCHECKED, i);
    int ret = lua_check_personal_data((lua_State *)L, (char *)cache.ptr, user, personal, herr);
    if (ret != CKB_SUCCESS)
    {
        DEBUG_PRINT("[ERROR] mismatched input/output. (cell = %lu)", i);
        return ret;
    }
    return CKB_SUCCESS;
}

#endif