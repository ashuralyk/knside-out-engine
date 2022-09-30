#ifndef CKB_FLAG_REQUEST
#define CKB_FLAG_REQUEST

#include "../common/header.h"
#include "../common/lua_wrap.h"
#include "../common/high_level.h"

int verify_request_data(uint8_t *cache, lua_State *L, int herr, mol_seg_t script_args, uint8_t code_hash[HASH_SIZE])
{
    ckb_debug("request/check mode");
    int ret = CKB_SUCCESS;
    // check flag2
    uint8_t caller_lockhash[HASH_SIZE];
    CHECK_RET(ckbx_flag2_load_caller_lockhash(script_args.ptr + 1, script_args.size - 1, caller_lockhash));
    // find lock_hash of this cell
    uint8_t expected_hash[HASH_SIZE];
    uint64_t len = HASH_SIZE;
    ckb_load_script_hash(expected_hash, &len, 0);
    // find cell position in inputs
    size_t indices[MAX_SAME_REQUEST_COUNT];
    CHECK_RET(ckbx_check_request_hash_exist(CKB_SOURCE_INPUT, expected_hash, indices));
    uint8_t output_lockhash[HASH_SIZE];
    for (size_t i = 0; indices[i] > 0; ++i)
    {
        len = HASH_SIZE;
        ret = ckb_load_cell_by_field(
            output_lockhash, &len, 0, indices[i], CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);
        if (ret != CKB_SUCCESS || memcmp(output_lockhash, caller_lockhash, HASH_SIZE))
        {
            return ERROR_LOADING_SCRIPT_HASH;
        }
    }
    return CKB_SUCCESS;
}

#endif