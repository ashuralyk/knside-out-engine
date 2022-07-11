#include "../common/header.h"
#include "../common/lua_wrap.h"
#include "../common/high_level.h"
 
int _apply_lock_args(void *L, size_t i, mol_seg_t lock_args, mol_seg_t data, int herr)
{
    ckb_debug("apply");
    if (lock_args.ptr[0] != FLAG_REQUEST)
    {
        return ERROR_REQUEST_FLAG;
    }
    int ret = CKB_SUCCESS;
    uint8_t function_call[MAX_FUNCTION_CALL_SIZE] = { 0 };
    CHECK_RET(ckbx_flag2_load_function_call(
        lock_args.ptr + 1, lock_args.size - 1, function_call, MAX_FUNCTION_CALL_SIZE
    ));
    uint8_t lock_hash[HASH_SIZE];
    CHECK_RET(ckbx_flag2_load_caller_lockhash(lock_args.ptr + 1, lock_args.size - 1, lock_hash));
    CHECK_RET(lua_inject_json_context((lua_State *)L, data.ptr, data.size, "data"));
    CHECK_RET(lua_inject_auth_context((lua_State *)L, lock_hash, "sender"));
    if (luaL_loadstring((lua_State *)L, (const char *)function_call) || lua_pcall((lua_State *)L, 0, 0, herr))
    {
        char debug[512];
        sprintf(debug, "invalid reqeust function call. (cell = %lu, payload = %s)", i, function_call);
        ckb_debug(debug);
        return ERROR_APPLY_LUA_REQUEST;
    }
    return CKB_SUCCESS;
}

int verify_global_data(uint8_t *cache, lua_State *L, int herr, mol_seg_t script_args, uint8_t code_hash[HASH_SIZE])
{
    int ret = CKB_SUCCESS;
    // check flag0
    uint8_t project_id[HASH_SIZE];
    CHECK_RET(ckbx_flag0_load_project_id(script_args.ptr + 1, script_args.size - 1, project_id));
    // check cell mod
    uint64_t len = MAX_CACHE_SIZE;
    ret = ckb_load_cell_data(cache, &len, 0, 0, CKB_SOURCE_GROUP_INPUT);
    // global data update mode
    if (ret == CKB_SUCCESS)
    {
        ckb_debug("update mode");
        CHECK_RET(lua_inject_json_context(L, cache, len, "global"));
        size_t index;
        CHECK_RET(ckbx_check_project_exist(CKB_SOURCE_CELL_DEP, project_id, &index));
        if (index == (size_t)-1)
        {
            return ERROR_NO_DEPLOYMENT_CELL;
        }
        mol_seg_t lua_code_seg;
        CHECK_RET(ckbx_load_project_lua_code(cache, MAX_CACHE_SIZE, CKB_SOURCE_CELL_DEP, index, &lua_code_seg));
        // load lua code into lua_vm
        CHECK_RET(lua_load_project_code(L, lua_code_seg.ptr, lua_code_seg.size, herr));
        // inject owner hash
        uint8_t lock_hash[HASH_SIZE];
        len = HASH_SIZE;
        ckb_load_cell_by_field(lock_hash, &len, 0, index, CKB_SOURCE_CELL_DEP, CKB_CELL_FIELD_LOCK_HASH);
        CHECK_RET(lua_inject_auth_context(L, lock_hash, "owner"));
        // apply each of requests
        ApplyParams apply = { L, herr, _apply_lock_args };
        CHECK_RET(ckbx_apply_all_lock_args_by_code_hash(cache, MAX_CACHE_SIZE, CKB_SOURCE_INPUT, code_hash, &apply));
        // check input/output global data
        len = MAX_CACHE_SIZE;
        CHECK_RET(ckb_load_cell_data(cache, &len, 0, 0, CKB_SOURCE_GROUP_OUTPUT));
        CHECK_RET(lua_check_global_data(L, "return msg.global", cache, len, herr));
    }
    // global data initial mode
    else if (ret == CKB_INDEX_OUT_OF_BOUND)
    {
        ckb_debug("initial mode");
        size_t index;
        CHECK_RET(ckbx_check_project_exist(CKB_SOURCE_OUTPUT, project_id, &index));
        if (index == (size_t)-1)
        {
            return ERROR_NO_DEPLOYMENT_CELL;
        }
        mol_seg_t lua_code_seg;
        CHECK_RET(ckbx_load_project_lua_code(cache, MAX_CACHE_SIZE, CKB_SOURCE_OUTPUT, index, &lua_code_seg));
        // load lua code into lua_vm
        CHECK_RET(lua_load_project_code(L, lua_code_seg.ptr, lua_code_seg.size, herr));
        // check global data format
        len = MAX_CACHE_SIZE;
        CHECK_RET(ckb_load_cell_data(cache, &len, 0, 0, CKB_SOURCE_GROUP_OUTPUT));
        CHECK_RET(lua_check_global_data(L, "return construct()", cache, len, herr));
    }
    else
    {
        CHECK_RET(ret);
    }
}
