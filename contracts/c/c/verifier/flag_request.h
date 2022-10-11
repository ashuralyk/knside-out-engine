#ifndef CKB_FLAG_REQUEST
#define CKB_FLAG_REQUEST

#include "../common/header.h"
#include "../common/lua_wrap.h"
#include "../common/high_level.h"

int verify_request_data(
    uint8_t *cache, lua_State *L, int herr, mol_seg_t flag_seg, uint8_t code_hash[HASH_SIZE])
{
    ckb_debug("request/check mode");
    int ret = CKB_SUCCESS;
    uint8_t project_id[HASH_SIZE];
    CHECK_RET(ckbx_identity_load_project_id(flag_seg.ptr, flag_seg.size, project_id));
    for (size_t i = 0; true; ++i)
    {
        size_t len = sizeof(uint64_t);
        ret = ckb_load_cell_by_field(
            NULL, &len, 0, i, CKB_SOURCE_GROUP_INPUT, CKB_CELL_FIELD_CAPACITY);
        if (ret == CKB_INDEX_OUT_OF_BOUND)
        {
            break;
        }
        CHECK_RET(ckbx_check_personal_exist(
            cache, MAX_CACHE_SIZE, CKB_SOURCE_GROUP_INPUT, i, code_hash, project_id));
    }
    return CKB_SUCCESS;
}

#endif