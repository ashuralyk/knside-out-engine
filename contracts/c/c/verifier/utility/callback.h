#ifndef CKB_LUA_INTERNAL
#define CKB_LUA_INTERNAL

#include "../../common/header.h"
#include "../../common/lua_wrap.h"
#include "../../common/high_level.h"

int _inject_function_celldeps_array_context(
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
    uint8_t lock_hashes[HASH_SIZE][MAX_CELLDEP_COUNT];
    CHECK_RET(ckbx_request_load_function_celldeps_lockhash(
        request_seg.ptr, request_seg.size, lock_hashes, &count));
    lua_newtable(L);
    for (size_t i = 0; i < count; ++i)
    {
        // key
        lua_pushhexstrng(L, lock_hashes[i], HASH_SIZE);
        // value
        mol_seg_t celldep_data;
        CHECK_RET(ckbx_check_function_celldep_exist(
            cache, len, code_hash, project_id, lock_hashes[i], &celldep_data));
        CHECK_RET(_json_to_table(
            L, (char *)celldep_data.ptr, celldep_data.size, NULL));
        // libraries[key] = value
        lua_settable(L, -2);
    }
    lua_setfield(L, -2, name);
    lua_setglobal(L, LUA_KOC);
    return CKB_SUCCESS;
}

int _inject_floating_lockhashes_array_context(lua_State *L, mol_seg_t request_seg, const char *name)
{
    lua_getglobal(L, LUA_KOC);
    if (!lua_istable(L, -1))
    {
        lua_newtable(L);
    }
    int ret = CKB_SUCCESS;
    size_t count = 0;
    uint8_t lock_hashes[HASH_SIZE][MAX_FLOATING_COUNT];
    CHECK_RET(ckbx_request_load_floating_lockhashes(
        request_seg.ptr, request_seg.size, lock_hashes, &count));
    lua_newtable(L);
    for (size_t i = 0; i < count; ++i)
    {
        // value
        lua_pushhexstrng(L, lock_hashes[i], HASH_SIZE);
        // candidates[i] = value
        lua_rawseti(L, -2, i + 1);
    }
    lua_setfield(L, -2, name);
    lua_setglobal(L, LUA_KOC);
    return CKB_SUCCESS;
}

int _inject_cells_array_context(lua_State *L, mol_seg_t request_seg, const char *name)
{
    lua_getglobal(L, LUA_KOC);
    if (!lua_istable(L, -1))
    {
        lua_newtable(L);
    }
    int ret = CKB_SUCCESS;
    mol_seg_t cells_seg;
    CHECK_RET(ckbx_request_load_cells(request_seg.ptr, request_seg.size, &cells_seg));
    if (MolReader_CellVec_verify(&cells_seg, false))
    {
        uint8_t lock_hash[HASH_SIZE];
        size_t count = MolReader_CellVec_length(&cells_seg);
        lua_newtable(L);
        for (size_t i = 0; i < count; ++i)
        {
            lua_newtable(L);
            // push `owner`
            mol_seg_t cell_seg = MolReader_CellVec_get(&cells_seg, i).seg;
            mol_seg_t owner_lockscript_seg = MolReader_Cell_get_owner_lockscript(&cell_seg);
            mol_seg_t owner_lockscript_bytes_seg = MolReader_String_raw_bytes(&owner_lockscript_seg);
            blake2b(
                lock_hash, HASH_SIZE, owner_lockscript_bytes_seg.ptr, owner_lockscript_bytes_seg.size,
                NULL, 0);
            lua_pushhexstrng(L, lock_hash, HASH_SIZE);
            lua_setfield(L, -2, "owner");
            // push `data`
            mol_seg_t data_seg = MolReader_Cell_get_data(&cell_seg);
            if (MolReader_StringOpt_is_none(&data_seg))
            {
                lua_pushnil(L);
            }
            else
            {
                mol_seg_t data_bytes_seg = MolReader_String_raw_bytes(&data_seg);
                CHECK_RET(_json_to_table(
                    L, (char *)data_bytes_seg.ptr, data_bytes_seg.size, NULL));
            }
            lua_setfield(L, -2, "data");
            // inputs[i] = value
            lua_rawseti(L, -2, i);
        }
    }
    lua_setfield(L, -2, name);
    lua_setglobal(L, LUA_KOC);
    return CKB_SUCCESS;
}

int _process_function_result(lua_State *L)
{
    int ret = CKB_SUCCESS;
    // check function result
    int result_top = lua_gettop(L);
    bool use_koc_inputs = true;
    if (lua_istable(L, result_top))
    {
        lua_getglobal(L, LUA_KOC);
        int koc = lua_gettop(L);
        // check `driver`
        lua_getfield(L, result_top, "driver");
        if (lua_isstring(L, -1))
        {
            lua_setfield(L, koc, "driver");
        }
        lua_settop(L, koc);
        // check `global`
        lua_getfield(L, -2, "global");
        if (lua_istable(L, -1))
        {
            lua_setfield(L, koc, "global");
        }
        lua_settop(L, koc);
        // check `outputs`
        lua_getfield(L, result_top, "outputs");
        if (lua_istable(L, -1))
        {
            int source = lua_gettop(L);
            lua_addoffset(L, LUA_OUTPUT_OFFSET, luaL_len(L, source));
            lua_getglobal(L, LUA_UNCHECKED);
            int target = lua_gettop(L);
            CHECK_RET(lua_append_table(L, source, target));
            use_koc_inputs = false;
        }
    }
    if (use_koc_inputs)
    {
        // pull out unchecked
        lua_getglobal(L, LUA_UNCHECKED);
        int target = lua_gettop(L);
        // pull out inputs from KOC context
        lua_getglobal(L, LUA_KOC);
        lua_getfield(L, -1, "inputs");
        int source = lua_gettop(L);
        lua_addoffset(L, LUA_OUTPUT_OFFSET, luaL_len(L, source));
        // append inputs into output_cells
        CHECK_RET(lua_append_table(L, source, target));
    }
    lua_addoffset(L, LUA_INPUT_OFFSET, 1);
    return CKB_SUCCESS;
}

int util_apply_request_args(
    void *args, size_t i, mol_seg_t cache, mol_seg_t lock_args, mol_seg_t request_seg, int herr)
{
    if (lock_args.ptr[0] != FLAG_REQUEST)
    {
        return ERROR_REQUEST_FLAG;
    }
    LuaParams *params = (LuaParams *)args;
    lua_State *L = (lua_State *)params->L;
    int recover_top = lua_gettop(L);
    int ret = CKB_SUCCESS;
    CHECK_RET(_inject_cells_array_context(L, request_seg, "inputs"));
    CHECK_RET(_inject_floating_lockhashes_array_context(L, request_seg, "candidates"));
    CHECK_RET(_inject_function_celldeps_array_context(
        L, cache.ptr, cache.size, request_seg, params->code_hash, params->project_id, "libraries"));
    // dumplicate KOC into backup
    lua_getglobal(L, LUA_KOC);
    CHECK_RET(lua_deep_copy_table(L));
    lua_setglobal(L, LUA_KOC_BACKUP);
    lua_pop(L, 1);
    // fetch user request method function
    uint8_t function_call[MAX_FUNCTION_CALL_SIZE] = "";
    CHECK_RET(ckbx_request_load_function_call(
        request_seg.ptr, request_seg.size, function_call, MAX_FUNCTION_CALL_SIZE));
    ckb_debug((char *)function_call);
    if (luaL_loadstring(L, (char *)function_call) || lua_pcall(L, 0, 1, herr))
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
    }
    // recover KOC from backup
    lua_getglobal(L, LUA_KOC_BACKUP);
    lua_setglobal(L, LUA_KOC);
    // process result to change unchecked status
    CHECK_RET(_process_function_result(L));
    lua_settop(L, recover_top);
    return CKB_SUCCESS;
}

int util_apply_personal_data(
    void *L, size_t i, mol_seg_t cache, mol_seg_t user, mol_seg_t data, int herr)
{
    snprintf((char *)cache.ptr, cache.size, "return %s[%lu]", LUA_UNCHECKED, i);
    int ret = lua_check_personal_data((lua_State *)L, (char *)cache.ptr, user, data, herr);
    if (ret != CKB_SUCCESS)
    {
        DEBUG_PRINT("[ERROR] mismatched input/output. (cell = %lu)", i);
        return ret;
    }
    return CKB_SUCCESS;
}

#endif