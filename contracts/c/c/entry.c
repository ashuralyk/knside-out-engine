#include "lua_wrap.h"
#include "high_level.h"

int _apply_lock_args(void *L, size_t i, uint8_t *lock_args, size_t len, int herr)
{
    if (lock_args[0] != 2)
    {
        return ERROR_REQUEST_FLAG;
    }
    int ret = CKB_SUCCESS;
    uint8_t function_call[MAX_FUNCTION_CALL_SIZE] = { 0 };
    CHECK_RET(ckbx_flag2_load_function_call(lock_args + 1, len - 1, function_call, MAX_FUNCTION_CALL_SIZE));
    if (luaL_loadstring((lua_State *)L, (const char *)function_call) || lua_pcall((lua_State *)L, 0, 0, herr))
    {
        char debug[512];
        sprintf(debug, "invalid reqeust function call. (cell = %lu, payload = %s)", i, function_call);
        ckb_debug(debug);
        return ERROR_APPLY_LUA_REQUEST;
    }
    return CKB_SUCCESS;
}

int lua_init(lua_State *L, int herr)
{
    luaL_openlibs(L);
    inject_ckb_functions(L);

    return 0;
}

int lua_verify(lua_State *L, int herr)
{
    // Fetch ckb script from context and point to "args" field
    uint8_t cache[MAX_CACHE_SIZE];
    uint8_t code_hash[HASH_SIZE];
    mol_seg_t script_args;
    int ret = CKB_SUCCESS;
    CHECK_RET(ckbx_load_script(cache, MAX_CACHE_SIZE, &script_args, code_hash));

    // Get flag from args and dipatch handler
    uint8_t flag = script_args.ptr[0];
    switch (flag)
    {
        // represent global data
        case 0:
        {
            // check flag0
            uint8_t project_id[HASH_SIZE];
            CHECK_RET(ckbx_flag0_load_project_id(script_args.ptr + 1, script_args.size - 1, project_id));
            // check cell mod
            uint64_t len = MAX_CACHE_SIZE;
            ret = ckb_load_cell_data(cache, &len, 0, 0, CKB_SOURCE_GROUP_INPUT);
            // global data update mod
            if (ret == CKB_SUCCESS)
            {
                cache[len] = '\0';
                CHECK_RET(lua_inject_project_context(L, (char *)cache));
                ApplyParams apply;
                apply.L = L;
                apply.herr = herr;
                apply.call = _apply_lock_args;
                CHECK_RET(ckbx_apply_all_lock_args_by_code_hash(cache, MAX_CACHE_SIZE, CKB_SOURCE_INPUT, code_hash, &apply));
                len = MAX_CACHE_SIZE;
                CHECK_RET(ckb_load_cell_data(cache, &len, 0, 0, CKB_SOURCE_GROUP_OUTPUT));
                CHECK_RET(lua_check_global_data(L, "return CONTEXT.Global", true, cache, len, herr));
            }
            // global data initial mod
            else if (ret == CKB_INDEX_OUT_OF_BOUND)
            {
                FindResult hash_check;
                CHECK_RET(ckbx_check_cell_type_hash_exist(CKB_SOURCE_OUTPUT, project_id, &hash_check));
                if (!hash_check.is_find)
                {
                    return ERROR_NO_DEPLOYMENT_CELL;
                }
                mol_seg_t lua_code_seg;
                CHECK_RET(ckbx_load_project_lua_code(cache, MAX_CACHE_SIZE, CKB_SOURCE_OUTPUT, hash_check.which, &lua_code_seg));
                // load lua code into lua_vm
                CHECK_RET(lua_load_project_code(L, lua_code_seg.ptr, lua_code_seg.size, herr));
                // check global data format
                len = MAX_CACHE_SIZE;
                CHECK_RET(ckb_load_cell_data(cache, &len, 0, 0, CKB_SOURCE_GROUP_OUTPUT));
                CHECK_RET(lua_check_global_data(L, "InitGlobal", false, cache, len, herr));
            }
            else
            {
                CHECK_RET(ret);
            }
        }
    }

    return CKB_SUCCESS;
}
