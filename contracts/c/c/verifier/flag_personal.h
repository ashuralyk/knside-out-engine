#ifndef CKB_FLAG_PERSONAL
#define CKB_FLAG_PERSONAL

#include "../common/header.h"
#include "../common/lua_wrap.h"
#include "../common/high_level.h"

int _apply_request_args(void *L, size_t i, mol_seg_t lock_args, mol_seg_t data, int herr)
{
    if (lock_args.ptr[0] != FLAG_REQUEST)
    {
        return ERROR_REQUEST_FLAG;
    }
    int ret = CKB_SUCCESS;
    uint8_t function_call[MAX_FUNCTION_CALL_SIZE] = PREFIX;
    CHECK_RET(ckbx_flag2_load_function_call(
        lock_args.ptr + 1, lock_args.size - 1,
        function_call + strlen(PREFIX), MAX_FUNCTION_CALL_SIZE - strlen(PREFIX)
    ));
    ckb_debug((const char *)function_call);
    uint8_t lock_hash[HASH_SIZE];
    CHECK_RET(ckbx_flag2_load_caller_lockhash(lock_args.ptr + 1, lock_args.size - 1, lock_hash));
    CHECK_RET(lua_inject_json_context(L, data.ptr, data.size, "data"));
    CHECK_RET(lua_inject_auth_context(L, lock_hash, "sender"));
    lua_getglobal(L, "_unchecked");
    if (i != luaL_len(L, -1) + 1)
    {
        return ERROR_UNCONTINUOUS_REQUEST;
    }
    int top = lua_gettop(L);
    if (luaL_loadstring(L, (const char *)function_call) || lua_pcall(L, 0, 1, herr))
    {
        DEBUG_PRINT("[ERROR] invalid reqeust function call. (cell = %lu, payload = %s)", i, function_call);
        return ERROR_APPLY_LUA_REQUEST;
    }
    // the return must be a table value
    if (lua_gettop(L) != top + 1 || !lua_istable(L, -1))
    {
        DEBUG_PRINT("[ERROR] invalid function return. (cell = %lu, payload = %s)", i, function_call);
        return ERROR_APPLY_LUA_REQUEST;
    }
    lua_rawseti(L, -2, i);
    return CKB_SUCCESS;
}

int _apply_personal_data(void *L, size_t i, mol_seg_t owner, mol_seg_t data, int herr)
{
    int ret = CKB_SUCCESS;
    lua_getglobal(L, "_compare_unchecked");
    lua_pushinteger(L, i);
    // create data table for comparision
    lua_newtable(L);
    char hex[owner.size * 2];
    _to_hex(hex, owner.ptr, owner.size);
    lua_pushlstring(L, hex, owner.size * 2);
    lua_setfield(L, -2, "owner");
    if (data.ptr != NULL)
    {
        if (data.size > 0)
        {
            CHECK_RET(_json_to_table(L, (char *)data.ptr, data.size, NULL));
        }
        else
        {
            lua_newtable(L);
        }
        lua_setfield(L, -2, "data");
    }
    // compare with unchecked table
    lua_pcall(L, 2, 1, herr);
    if (!lua_toboolean(L, -1))
    {
        DEBUG_PRINT("[ERROR] mismatched input/output. (cell = %lu)", i);
        return ERROR_CHECK_LUA_PERSONAL_DATA;
    }
    return CKB_SUCCESS;
}

int _ckb_cost(lua_State *L)
{
    uint64_t ckb = (size_t)(luaL_checknumber(L, -1) * CKB_ONE);
    lua_getglobal(L, "_unchecked");
    size_t i = luaL_len(L, -1) + 1;
    uint64_t offerred_ckb;
    uint64_t size = sizeof(offerred_ckb);
    int ret = ckb_load_cell_by_field(&offerred_ckb, &size, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_CAPACITY);
    if (ret != CKB_SUCCESS)
    {
        lua_pushboolean(L, false);
        return 1;
    }
    uint64_t occupied_ckb;
    ret = ckb_load_cell_by_field(&occupied_ckb, &size, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_OCCUPIED_CAPACITY);
    if (ret != CKB_SUCCESS)
    {
        lua_pushboolean(L, false);
        return 1;
    }
    // check CKB fee amount
    if (occupied_ckb + ckb > offerred_ckb)
    {
        DEBUG_PRINT(
            "[ERROR] need more %4.f ckb. (cell = %lu)", 
            (occupied_ckb + ckb - offerred_ckb) / (double)CKB_ONE, i
        );
        lua_pushboolean(L, false);
        return 1;
    }
    lua_pushboolean(L, true);
    return 1;
}

int inject_personal_operation(lua_State *L, int herr)
{
    const char *checker_chunck = " \
        _unchecked = {} \
        function _compare_unchecked(i, tab) \
            local unchecked = assert(_unchecked[i], 'output ' .. i .. ' has no corresponded input') \
            return _compare_tables(unchecked, tab) \
        end \
    ";
    if (luaL_loadstring(L, checker_chunck) || lua_pcall(L, 0, 0, herr))
    {
        ckb_debug("[ERROR] invalid personal checker chunck.");
        return ERROR_LUA_INIT;
    }
    // add ckb_cost method
    lua_getglobal(L, "msg");
    if (!lua_istable(L, -1))
    {
        lua_newtable(L);
    }
    lua_pushcfunction(L, _ckb_cost);
    lua_setfield(L, -2, "ckb_cost");
    // reset `msg`
    lua_setglobal(L, "msg");
    return CKB_SUCCESS;
}

int verify_personal_data(uint8_t *cache, lua_State *L, int herr, mol_seg_t script_args, uint8_t code_hash[HASH_SIZE])
{
    int ret = CKB_SUCCESS;
    // check flag1
    uint8_t project_id[HASH_SIZE];
    CHECK_RET(ckbx_flag1_load_project_id(script_args.ptr + 1, script_args.size - 1, project_id));
    // check wether inputs contain same script
    uint64_t len = MAX_CACHE_SIZE;
    ret = ckb_load_cell_by_field(cache, &len, 0, 0, CKB_SOURCE_GROUP_INPUT, CKB_CELL_FIELD_CAPACITY);
    // personal data update mode
    if (ret == CKB_SUCCESS)
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
        CHECK_RET(ckbx_check_global_exist(
            cache, MAX_CACHE_SIZE, CKB_SOURCE_INPUT, project_id, code_hash, &input_global_data
        ));
        CHECK_RET(lua_inject_json_context(L, input_global_data.ptr, input_global_data.size, "global"));
        // get lua code
        mol_seg_t lua_code_seg;
        CHECK_RET(ckbx_load_project_lua_code(
            cache, MAX_CACHE_SIZE, CKB_SOURCE_CELL_DEP, index, &lua_code_seg
        ));
        // load lua code into lua_vm
        CHECK_RET(lua_load_project_code(L, lua_code_seg.ptr, lua_code_seg.size, herr));
        // inject owner hash
        uint8_t owner_hash[HASH_SIZE];
        len = HASH_SIZE;
        ckb_load_cell_by_field(
            owner_hash, &len, 0, index, CKB_SOURCE_CELL_DEP, CKB_CELL_FIELD_LOCK_HASH
        );
        CHECK_RET(lua_inject_auth_context(L, owner_hash, "owner"));
        // apply each of requests
        ApplyParams apply = { L, herr, _apply_request_args };
        CHECK_RET(ckbx_apply_lock_args_by_code_hash(
            cache, MAX_CACHE_SIZE, CKB_SOURCE_INPUT, code_hash, &apply
        ));
        // first cell from tx-outputs must be Global Cell as well
        mol_seg_t output_global_data;
        CHECK_RET(ckbx_check_global_exist(
            cache, MAX_CACHE_SIZE, CKB_SOURCE_OUTPUT, project_id, code_hash, &output_global_data
        ));
        // check input/output global data
        CHECK_RET(lua_check_global_data(
            L, "return msg.global", output_global_data.ptr, output_global_data.size, herr
        ));
        // check other outputs personal data
        apply.call = _apply_personal_data;
        CHECK_RET(ckbx_apply_personal_output_by_code_hash(
            cache, MAX_CACHE_SIZE, 1, code_hash, &apply
        ));
    }
    // personal/global data request mode
    else if (ret == CKB_INDEX_OUT_OF_BOUND)
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
    else
    {
        CHECK_RET(ret);
    }
    return CKB_SUCCESS;
}

#endif