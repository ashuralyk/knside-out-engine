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
    uint8_t data_hashes[HASH_SIZE][MAX_CELLDEP_COUNT];
    CHECK_RET(ckbx_request_load_function_celldeps(
        request_seg.ptr, request_seg.size, data_hashes, &count));
    lua_newtable(L);
    for (size_t i = 0; i < count; ++i)
    {
        // value
        mol_seg_t celldep_data;
        CHECK_RET(ckbx_check_function_celldep_exist(
            cache, len, code_hash, project_id, data_hashes[i], &celldep_data));
        CHECK_RET(_json_to_table(
            L, (char *)celldep_data.ptr, celldep_data.size, NULL));
        // libraries[i] = value
        lua_rawseti(L, -2, i + 1);
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
    if (MolReader_CellVec_verify(&cells_seg, false) == MOL_OK)
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
            lua_rawseti(L, -2, i + 1);
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
    void *args, size_t i, mol_seg_t cache, mol_seg_t _empty, mol_seg_t request_seg, int herr)
{
    LuaParams *params = (LuaParams *)args;
    lua_State *L = (lua_State *)params->L;
    if (lua_getoffset(L, LUA_INPUT_OFFSET) != i)
    {
        return ERROR_UNMATCHED_INPUT_OFFSET;
    }
    int recover_top = lua_gettop(L);
    int ret = CKB_SUCCESS;
    CHECK_RET(_inject_cells_array_context(L, request_seg, "inputs"));
    CHECK_RET(_inject_floating_lockhashes_array_context(L, request_seg, "candidates"));
    CHECK_RET(_inject_function_celldeps_array_context(
        L, cache.ptr, cache.size, request_seg, params->code_hash, params->project_id, "components"));
    // dumplicate KOC into backup
    lua_getglobal(L, LUA_KOC);
    CHECK_RET(lua_deep_copy_table(L));
    lua_setglobal(L, LUA_KOC_BACKUP);
    // fetch user request method function
    char function_call[MAX_FUNCTION_CALL_SIZE] = LUA_PREFIX;
    CHECK_RET(ckbx_request_load_function_call(
        request_seg.ptr, request_seg.size,
        function_call + strlen(LUA_PREFIX), MAX_FUNCTION_CALL_SIZE - strlen(LUA_PREFIX)));
    ckb_debug(function_call);
    if (luaL_loadstring(L, function_call) || lua_pcall(L, 0, 1, herr))
    {
        DEBUG_PRINT(
            "[ERROR] invalid request function call. (cell = %lu, payload = %s)", i, function_call);
        // uint64_t input_ckb, output_ckb;
        // int output_i = lua_getoffset(L, LUA_OUTPUT_OFFSET);
        // CHECK_RET(ckbx_get_parallel_cell_capacity(
        //     CKB_SOURCE_INPUT, false, i, CKB_SOURCE_OUTPUT, false, output_i, &input_ckb, &output_ckb));
        // if (input_ckb != output_ckb)
        // {
        //     return ERROR_UNMATCHED_REQUEST_CKB;
        // }
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
    void *args, size_t i, mol_seg_t cache, mol_seg_t user, mol_seg_t data, int herr)
{
    lua_State *L = (lua_State *)args;
    if (i < lua_getoffset(L, LUA_OUTPUT_OFFSET))
    {
        snprintf((char *)cache.ptr, cache.size, "return %s[%lu]", LUA_UNCHECKED, i);
        int ret = lua_check_personal_data(L, (char *)cache.ptr, user, data, herr);
        if (ret != CKB_SUCCESS)
        {
            DEBUG_PRINT("[ERROR] mismatched output cell. (cell = %lu)", i);
            return ret;
        }
    }
    return CKB_SUCCESS;
}

#endif