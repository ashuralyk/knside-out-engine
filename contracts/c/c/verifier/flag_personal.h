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
        ckb_debug("update mode");
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
        ApplyParams apply = { L, herr, _apply_lock_args };
        CHECK_RET(ckbx_apply_all_lock_args_by_code_hash(
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
    }
    // personal/global data request mode
    else if (ret == CKB_INDEX_OUT_OF_BOUND)
    {
        ckb_debug("request mode");
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
}
