#ifndef CKB_LUA_HIGH_LEVEL
#define CKB_LUA_HIGH_LEVEL

#include "header.h"
#include "blockchain.h"
#include "blake2b.h"
#include "../molecule/protocol.h"

typedef int (*ApplyFunc) (void *, size_t, mol_seg_t, mol_seg_t, int);

typedef struct
{
    void *L;
    int herr;
    ApplyFunc call;
} ApplyParams;

void _print_hex(const char *prefix, unsigned char *msg, int size) {
    char debug[1024] = "";
    char x[16];
    int j = 0;
    for (int i = 0; i < size; ++i) {
        sprintf(x, "%02x", (int)msg[i]);
        memcpy(&debug[j], x, strlen(x));
        j += strlen(x);
    }
    char print[2048];
    sprintf(print, "%s = \"%s\"", prefix, debug);
    ckb_debug(print);
}

int ckbx_flag0_load_project_id(uint8_t *cache, size_t len, uint8_t project_id[HASH_SIZE])
{
    mol_seg_t flag0_seg = { cache, len };
    if (MolReader_Flag_0_verify(&flag0_seg, false) != MOL_OK)
    {
        return ERROR_FLAG_0_BYTES;
    }
    mol_seg_t project_id_seg = MolReader_Flag_0_get_project_id(&flag0_seg);
    memcpy(project_id, project_id_seg.ptr, project_id_seg.size);
    return CKB_SUCCESS;
}

int ckbx_flag1_load_project_id(uint8_t *cache, size_t len, uint8_t project_id[HASH_SIZE])
{
    mol_seg_t flag1_seg = { cache, len };
    if (MolReader_Flag_1_verify(&flag1_seg, false) != MOL_OK)
    {
        return ERROR_FLAG_1_BYTES;
    }
    mol_seg_t project_id_seg = MolReader_Flag_1_get_project_id(&flag1_seg);
    memcpy(project_id, project_id_seg.ptr, project_id_seg.size);
    return CKB_SUCCESS;
}

int ckbx_flag2_load_function_call(uint8_t *cache, size_t len, uint8_t *function_call, size_t size)
{
    mol_seg_t flag2_seg = { cache, len };
    if (MolReader_Flag_2_verify(&flag2_seg, false) != MOL_OK)
    {
        return ERROR_FLAG_2_BYTES;
    }
    mol_seg_t function_call_seg = MolReader_Flag_2_get_function_call(&flag2_seg);
    mol_seg_t function_call_bytes_seg = MolReader_String_raw_bytes(&function_call_seg);
    if (function_call_bytes_seg.size > size)
    {
        return ERROR_FLAG_2_BYTES;
    }
    memcpy(function_call, function_call_bytes_seg.ptr, function_call_bytes_seg.size);
    return CKB_SUCCESS;
}

int ckbx_flag2_load_caller_lockhash(uint8_t *cache, size_t len, uint8_t lock_hash[HASH_SIZE])
{
    mol_seg_t flag2_seg = { cache, len };
    if (MolReader_Flag_2_verify(&flag2_seg, false) != MOL_OK)
    {
        return ERROR_FLAG_2_BYTES;
    }
    mol_seg_t caller_lockscript_seg = MolReader_Flag_2_get_caller_lockscript(&flag2_seg);
    mol_seg_t caller_lockscript_bytes_seg = MolReader_String_raw_bytes(&caller_lockscript_seg);
    blake2b(
        lock_hash, HASH_SIZE, caller_lockscript_bytes_seg.ptr, caller_lockscript_bytes_seg.size,
        NULL, 0
    );
    return CKB_SUCCESS;
}

int ckbx_load_script(uint8_t *cache, size_t len, mol_seg_t *args_seg, uint8_t code_hash[HASH_SIZE])
{
    int ret = ckb_load_script(cache, &len, 0);
    if (ret != CKB_SUCCESS || len > MAX_CACHE_SIZE)
    {
        return ERROR_LOADING_SCRIPT;
    }
    mol_seg_t script_seg = { cache, len };
    mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
    memcpy(code_hash, code_hash_seg.ptr, HASH_SIZE);
    mol_seg_t script_args_seg = MolReader_Script_get_args(&script_seg);
    mol_seg_t script_args_bytes_seg = MolReader_Bytes_raw_bytes(&script_args_seg);
    if (script_args_bytes_seg.size < 1)
    {
        return ERROR_LUA_SCRIPT_ARGS;
    }
    *args_seg = script_args_bytes_seg;
    return CKB_SUCCESS;
}

int ckbx_apply_lock_args_by_code_hash(
    uint8_t *cache, size_t len, size_t source, uint8_t code_hash[HASH_SIZE], ApplyParams *callback
) {
    for (size_t i = 0; true; ++i)
    {
        size_t _len = len;
        int ret = ckb_load_cell_by_field(cache, &_len, 0, i, source, CKB_CELL_FIELD_LOCK);
        if (ret == CKB_INDEX_OUT_OF_BOUND)
        {
            break;
        }
        if (ret != CKB_SUCCESS || _len > len)
        {
            return ERROR_LOADING_REQUEST_CELL;
        }
        mol_seg_t script_seg = { cache, _len };
        mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
        if (memcmp(code_hash, code_hash_seg.ptr, HASH_SIZE) == 0)
        {
            mol_seg_t script_args_seg = MolReader_Script_get_args(&script_seg);
            mol_seg_t script_args_bytes_seg = MolReader_Bytes_raw_bytes(&script_args_seg);
            if (script_args_bytes_seg.size < 1)
            {
                return ERROR_LUA_SCRIPT_ARGS;
            }
            uint8_t *json_data = cache + _len;
            size_t json_len = len - _len;
            ret = ckb_load_cell_data(json_data, &json_len, 0, i, source);
            if (ret != CKB_SUCCESS || json_len > len - _len)
            {
                return ERROR_LOADING_REQUEST_CELL;
            }
            mol_seg_t data = { json_data, json_len };
            CHECK_RET(callback->call(callback->L, i, script_args_bytes_seg, data, callback->herr));
        }
    }
    return CKB_SUCCESS;
}

int ckbx_apply_personal_output_by_code_hash(
    uint8_t *cache, size_t len, size_t offset, uint8_t code_hash[HASH_SIZE], ApplyParams *callback
) {
    uint8_t lock_hash[HASH_SIZE];
    mol_seg_t personal_owner = { lock_hash, HASH_SIZE };
    for (size_t i = offset; true; ++i)
    {
        size_t _len = len;
        int ret = ckb_load_cell_by_field(cache, &_len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE);
        if (ret == CKB_INDEX_OUT_OF_BOUND)
        {
            break;
        }
        ckb_load_cell_by_field(
            personal_owner.ptr, (uint64_t *)&personal_owner.size, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH
        );
        // burned empty cell
        if (ret == CKB_ITEM_MISSING)
        {
            mol_seg_t empty = { NULL, 0 };
            CHECK_RET(callback->call(callback->L, i, personal_owner, empty, callback->herr));
            break;
        }
        if (ret != CKB_SUCCESS || _len > MAX_CACHE_SIZE)
        {
            return ERROR_LOADING_PERSONAL_CELL;
        }
        mol_seg_t script_seg = { cache, _len };
        mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
        if (memcmp(code_hash, code_hash_seg.ptr, HASH_SIZE))
        {
            return ERROR_LOADING_PERSONAL_CELL;
        }
        // check validation of personal type_scirpt
        mol_seg_t script_args_seg = MolReader_Script_get_args(&script_seg);
        mol_seg_t script_args_bytes_seg = MolReader_Bytes_raw_bytes(&script_args_seg);
        if (script_args_bytes_seg.size < 1 || script_args_bytes_seg.ptr[0] != FLAG_PERSONAL)
        {
            return ERROR_LUA_SCRIPT_ARGS;
        }
        mol_seg_t flag1_seg = { script_args_bytes_seg.ptr + 1, script_args_bytes_seg.size - 1 };
        if (MolReader_Flag_1_verify(&flag1_seg, false) != MOL_OK)
        {
            return ERROR_FLAG_1_BYTES;
        }
        // non-burned cell
        _len = len;
        ckb_load_cell_data(cache, &_len, 0, i, CKB_SOURCE_OUTPUT);
        mol_seg_t data = { cache, _len };
        CHECK_RET(callback->call(callback->L, i, personal_owner, data, callback->herr));
    }
    return CKB_SUCCESS;
}

int ckbx_check_project_exist(size_t source, uint8_t expected_hash[HASH_SIZE], size_t *which)
{
    uint8_t type_hash[HASH_SIZE];
    uint64_t len = HASH_SIZE;
    for (size_t i = 0; true; ++i)
    {
        int ret = 
            ckb_load_cell_by_field(type_hash, &len, 0, i, source, CKB_CELL_FIELD_TYPE_HASH);
        if (ret == CKB_INDEX_OUT_OF_BOUND)
        {
            *which = -1;
            break;
        }
        else if (ret != CKB_SUCCESS || len != HASH_SIZE)
        {
            return ERROR_NO_DEPLOYMENT_CELL;
        }
        if (memcmp(type_hash, expected_hash, HASH_SIZE) == 0)
        {
            *which = i;
            break;
        }
    }
    return CKB_SUCCESS;
}

int ckbx_check_request_exist(uint8_t *cache, size_t len, size_t source, size_t i, mol_seg_t *request_seg)
{
    int ret = ckb_load_cell_by_field(cache, &len, 0, i, source, CKB_CELL_FIELD_LOCK);
    if (ret != CKB_SUCCESS || len > MAX_CACHE_SIZE)
    {
        return ERROR_LOADING_SCRIPT;
    }
    mol_seg_t script_seg = { cache, len };
    mol_seg_t script_args_seg = MolReader_Script_get_args(&script_seg);
    mol_seg_t script_args_bytes_seg = MolReader_Bytes_raw_bytes(&script_args_seg);
    if (script_args_bytes_seg.size < 1 || script_args_bytes_seg.ptr[0] != FLAG_REQUEST)
    {
        return ERROR_REQUEST_ARGS;
    }
    if (request_seg)
    {
        *request_seg = script_args_bytes_seg;
    }
    return CKB_SUCCESS;
}

int ckbx_check_global_exist(
    uint8_t *cache, size_t len, uint8_t source, uint8_t expected_project_id[HASH_SIZE], 
    uint8_t expected_code_hash[HASH_SIZE], mol_seg_t *global_data
) {
    int ret = ckb_load_cell_by_field(cache, &len, 0, 0, source, CKB_CELL_FIELD_TYPE);
    if (ret != CKB_SUCCESS || len > MAX_CACHE_SIZE)
    {
        return ERROR_LOADING_GLOBAL_CELL;
    }
    mol_seg_t script_seg = { cache, len };
    mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
    if (memcmp(expected_code_hash, code_hash_seg.ptr, HASH_SIZE))
    {
        return ERROR_LOADING_GLOBAL_CELL;
    }
    mol_seg_t script_args_seg = MolReader_Script_get_args(&script_seg);
    mol_seg_t script_args_bytes_seg = MolReader_Bytes_raw_bytes(&script_args_seg);
    if (script_args_bytes_seg.size < 1 || script_args_bytes_seg.ptr[0] != FLAG_GLOBAL)
    {
        return ERROR_GLOBAL_ARGS;
    }
    uint8_t project_id[HASH_SIZE];
    CHECK_RET(ckbx_flag0_load_project_id(
        script_args_bytes_seg.ptr + 1, script_args_bytes_seg.size - 1, project_id
    ));
    if (memcmp(expected_project_id, project_id, HASH_SIZE))
    {
        return ERROR_GLOBAL_ARGS;
    }
    len = MAX_CACHE_SIZE;
    ret = ckb_load_cell_data(cache, &len, 0, 0, source);
    if (ret != CKB_SUCCESS || len > MAX_CACHE_SIZE)
    {
        return ERROR_LOADING_GLOBAL_CELL;
    }
    mol_seg_t data = { cache, len };
    *global_data = data;
    return CKB_SUCCESS;
}

int ckbx_check_reqeust_hash_exist(
    uint8_t source, uint8_t expected_hash[HASH_SIZE], size_t indices[MAX_SAME_REQUEST_COUNT]
) {
    uint8_t lock_hash[HASH_SIZE];
    uint64_t len = HASH_SIZE;
    // valid offset of request lock_hash starts from 1, so fully ZERO means NOT-FOUND for indices
    memset(indices, 0, sizeof(size_t) * MAX_SAME_REQUEST_COUNT);
    size_t j = 0;
    for (size_t i = 1; true; ++i)
    {
        int ret = ckb_load_cell_by_field(lock_hash, &len, 0, i, source, CKB_CELL_FIELD_LOCK_HASH);
        if (ret == CKB_INDEX_OUT_OF_BOUND)
        {
            break;
        }
        if (ret != CKB_SUCCESS)
        {
            return ERROR_LOADING_SCRIPT;
        }
        if (memcmp(lock_hash, expected_hash, HASH_SIZE) == 0)
        {
            if (j >= MAX_SAME_REQUEST_COUNT)
            {
                return ERROR_REQUEST_EXCESSIVE;
            }
            indices[j++] = i;
        }
    }
    size_t empty[MAX_SAME_REQUEST_COUNT] = { 0 };
    if (memcmp(indices, empty, sizeof(empty)) == 0)
    {
        return ERROR_REQUEST_NOT_FOUND;
    }
    return CKB_SUCCESS;
}

int ckbx_load_project_lua_code(
    uint8_t *cache, size_t len, uint8_t source, size_t i, mol_seg_t *code_seg
) {
    int ret = ckb_load_cell_data(cache, &len, 0, i, source);
    if (ret != CKB_SUCCESS || len > MAX_CACHE_SIZE)
    {
        return ERROR_DEPLOYMENT_FORMAT;
    }
    mol_seg_t deployment_seg = { cache, len };
    if (MolReader_Deployment_verify(&deployment_seg, false) != MOL_OK)
    {
        return ERROR_DEPLOYMENT_FORMAT;
    }
    mol_seg_t lua_code_seg = MolReader_Deployment_get_code(&deployment_seg);
    *code_seg = MolReader_String_raw_bytes(&lua_code_seg);
    return CKB_SUCCESS;
}

#endif