#ifndef CKB_LUA_HIGH_LEVEL
#define CKB_LUA_HIGH_LEVEL

#include "header.h"
#include "blockchain.h"
#include "molecule/protocol.h"
#include "blake2b.h"

typedef int (*ApplyFunc) (void *, size_t, mol_seg_t, mol_seg_t, int);

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

typedef struct
{
    void *L;
    int herr;
    ApplyFunc call;
} ApplyParams;

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
    if (script_args_bytes_seg.size > MAX_CACHE_SIZE || script_args_bytes_seg.size < 1)
    {
        return ERROR_LUA_SCRIPT_ARGS;
    }
    *args_seg = script_args_bytes_seg;
    return CKB_SUCCESS;
}

int ckbx_apply_all_lock_args_by_code_hash(
    uint8_t *cache, size_t len, size_t source, uint8_t code_hash[HASH_SIZE], ApplyParams *callback
) {
    uint8_t json_data[MAX_JSON_SIZE] = { 0 };
    for (size_t i = 0; true; ++i)
    {
        size_t _len = len;
        int ret = ckb_load_cell_by_field(cache, &_len, 0, i, source, CKB_CELL_FIELD_LOCK);
        if (ret == CKB_INDEX_OUT_OF_BOUND)
        {
            break;
        }
        if (ret != CKB_SUCCESS || _len > MAX_CACHE_SIZE)
        {
            return ERROR_LOADING_REQUEST_CELL;
        }
        mol_seg_t script_seg = { cache, _len };
        mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
        if (memcmp(code_hash, code_hash_seg.ptr, HASH_SIZE) == 0)
        {
            mol_seg_t script_args_seg = MolReader_Script_get_args(&script_seg);
            mol_seg_t script_args_bytes_seg = MolReader_Bytes_raw_bytes(&script_args_seg);
            if (script_args_bytes_seg.size > MAX_CACHE_SIZE || script_args_bytes_seg.size < 1)
            {
                return ERROR_LUA_SCRIPT_ARGS;
            }
            _len = MAX_JSON_SIZE;
            ret = ckb_load_cell_data(json_data, &_len, 0, i, source);
            if (ret != CKB_SUCCESS || _len > MAX_JSON_SIZE)
            {
                return ERROR_LOADING_REQUEST_CELL;
            }
            mol_seg_t data = { json_data, _len };
            ret = callback->call(callback->L, i, script_args_bytes_seg, data, callback->herr);
            if (ret != CKB_SUCCESS)
            {
                return ret;
            }
        }
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

#endif