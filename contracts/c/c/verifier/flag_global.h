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
    uint64_t len = MAX_CACHE_SIZE;
    ret = ckb_load_cell_data(cache, &len, 0, 0, CKB_SOURCE_GROUP_INPUT);
    // global data update mode
    if (ret == CKB_SUCCESS)
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
    else if (ret == CKB_INDEX_OUT_OF_BOUND)
    {
        ckb_debug("global/initial mode");
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
    return CKB_SUCCESS;
}

#endif