#ifndef CKB_LUA_HIGH_LEVEL
#define CKB_LUA_HIGH_LEVEL

#include "header.h"
#include "blake2b.h"
#include "../molecule/protocol.h"

typedef int (*ApplyFunc)(void *, size_t, mol_seg_t, mol_seg_t, mol_seg_t, int);

typedef struct
{
    void *args;
    int herr;
    ApplyFunc call;
} ApplyParams;

void _print_hex(const char *prefix, unsigned char *msg, int size)
{
    char debug[1024] = "";
    char x[16];
    int j = 0;
    for (int i = 0; i < size; ++i)
    {
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
    mol_seg_t flag0_seg = {cache, len};
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
    mol_seg_t flag1_seg = {cache, len};
    if (MolReader_Flag_1_verify(&flag1_seg, false) != MOL_OK)
    {
        return ERROR_FLAG_1_BYTES;
    }
    mol_seg_t project_id_seg = MolReader_Flag_1_get_project_id(&flag1_seg);
    memcpy(project_id, project_id_seg.ptr, project_id_seg.size);
    return CKB_SUCCESS;
}

int ckbx_flag2_load_project_id(uint8_t *cache, size_t len, uint8_t project_id[HASH_SIZE])
{
    mol_seg_t flag1_seg = {cache, len};
    if (MolReader_Flag_2_verify(&flag1_seg, false) != MOL_OK)
    {
        return ERROR_FLAG_1_BYTES;
    }
    mol_seg_t project_id_seg = MolReader_Flag_2_get_project_id(&flag1_seg);
    memcpy(project_id, project_id_seg.ptr, project_id_seg.size);
    return CKB_SUCCESS;
}

int ckbx_request_load_function_call(uint8_t *cache, size_t len, uint8_t *function_call, size_t size)
{
    mol_seg_t request_seg = {cache, len};
    if (MolReader_Request_verify(&request_seg, false) != MOL_OK)
    {
        return ERROR_REQUEST_BYTES;
    }
    mol_seg_t function_call_seg = MolReader_Request_get_function_call(&request_seg);
    mol_seg_t function_call_bytes_seg = MolReader_String_raw_bytes(&function_call_seg);
    if (function_call_bytes_seg.size > size)
    {
        return ERROR_REQUEST_BYTES;
    }
    memcpy(function_call, function_call_bytes_seg.ptr, function_call_bytes_seg.size);
    return CKB_SUCCESS;
}

int ckbx_request_load_cells(uint8_t *cache, size_t len, mol_seg_t *cells_seg)
{
    mol_seg_t request_seg = {cache, len};
    if (MolReader_Request_verify(&request_seg, false) != MOL_OK)
    {
        return ERROR_REQUEST_BYTES;
    }
    *cells_seg = MolReader_Request_get_cells(&request_seg);
    return CKB_SUCCESS;
}

int ckbx_request_load_floating_lockhashes(
    uint8_t *cache, size_t len, uint8_t lock_hashes[HASH_SIZE][MAX_FLOATING_COUNT], size_t *count)
{
    mol_seg_t request_seg = {cache, len};
    if (MolReader_Request_verify(&request_seg, false) != MOL_OK)
    {
        return ERROR_REQUEST_BYTES;
    }
    mol_seg_t floating_lockscript_seg = MolReader_Request_get_floating_lockscripts(&request_seg);
    *count = MolReader_StringVec_length(&floating_lockscript_seg);
    if (*count > MAX_FLOATING_COUNT)
    {
        return ERROR_FLOATING_LOCKSCRIPT_EXCESSIVE;
    }
    for (size_t i = 0; i < *count; ++i)
    {
        mol_seg_t floating_lockscript_seg = MolReader_StringVec_get(&floating_lockscript_seg, i).seg;
        mol_seg_t floating_lockscript_bytes_seg = MolReader_String_raw_bytes(&floating_lockscript_seg);
        blake2b(
            lock_hashes[i], HASH_SIZE, floating_lockscript_bytes_seg.ptr, floating_lockscript_bytes_seg.size,
            NULL, 0);
    }
    return CKB_SUCCESS;
}

int ckbx_request_load_function_celldeps_lockhash(
    uint8_t *cache, size_t len, uint8_t lock_hashes[HASH_SIZE][MAX_CELLDEP_COUNT], size_t *count)
{
    mol_seg_t request_seg = {cache, len};
    if (MolReader_Request_verify(&request_seg, false) != MOL_OK)
    {
        return ERROR_REQUEST_BYTES;
    }
    mol_seg_t function_celldeps_seg = MolReader_Request_get_function_celldeps(&request_seg);
    *count = MolReader_StringVec_length(&function_celldeps_seg);
    if (*count > MAX_CELLDEP_COUNT)
    {
        return ERROR_FUNCTION_CELLDEP_EXCESSIVE;
    }
    for (size_t i = 0; i < *count; ++i)
    {
        mol_seg_t function_celldep_seg = MolReader_StringVec_get(&function_celldeps_seg, i).seg;
        mol_seg_t function_celldep_bytes_seg = MolReader_String_raw_bytes(&function_celldep_seg);
        blake2b(
            lock_hashes[i], HASH_SIZE, function_celldep_bytes_seg.ptr, function_celldep_bytes_seg.size,
            NULL, 0);
    }
    return CKB_SUCCESS;
}

int ckbx_load_script(uint8_t *cache, size_t len, mol_seg_t *args_seg, uint8_t code_hash[HASH_SIZE])
{
    int ret = ckb_load_script(cache, &len, 0);
    if (ret != CKB_SUCCESS || len > MAX_CACHE_SIZE)
    {
        return ERROR_LOADING_SCRIPT;
    }
    mol_seg_t script_seg = {cache, len};
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
    uint8_t *cache, size_t len, size_t source, uint8_t code_hash[HASH_SIZE], ApplyParams *callback)
{
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
        mol_seg_t script_seg = {cache, _len};
        mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
        if (memcmp(code_hash, code_hash_seg.ptr, HASH_SIZE) == 0)
        {
            mol_seg_t script_args_seg = MolReader_Script_get_args(&script_seg);
            mol_seg_t script_args_bytes_seg = MolReader_Bytes_raw_bytes(&script_args_seg);
            if (script_args_bytes_seg.size < 1)
            {
                return ERROR_LUA_SCRIPT_ARGS;
            }
            uint8_t *request_data = cache + _len;
            size_t request_len = len - _len;
            ret = ckb_load_cell_data(request_data, &request_len, 0, i, source);
            if (ret != CKB_SUCCESS || request_len > len - _len)
            {
                return ERROR_LOADING_REQUEST_CELL;
            }
            mol_seg_t data = {request_data, request_len};
            mol_seg_t callback_cache = {data.ptr + data.size, len - _len - data.size};
            CHECK_RET(callback->call(
                callback->args, i, callback_cache, script_args_bytes_seg, data, callback->herr));
        }
    }
    return CKB_SUCCESS;
}

int ckbx_apply_personal_output_by_code_hash(
    uint8_t *cache, size_t len, size_t offset, uint8_t code_hash[HASH_SIZE], ApplyParams *callback)
{
    uint8_t lock_hash[HASH_SIZE];
    mol_seg_t personal_owner = {lock_hash, HASH_SIZE};
    for (size_t i = offset; true; ++i)
    {
        size_t _len = len;
        int ret = ckb_load_cell_by_field(cache, &_len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE);
        if (ret == CKB_INDEX_OUT_OF_BOUND)
        {
            break;
        }
        ckb_load_cell_by_field(
            personal_owner.ptr, (uint64_t *)&personal_owner.size, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);
        // burned empty cell
        if (ret == CKB_ITEM_MISSING)
        {
            // if change cell index = i, skip this check
            ret = ckb_load_cell_by_field(NULL, &_len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_TYPE);
            if (ret == CKB_ITEM_MISSING)
            {
                continue;
            }
            _len = len;
            ret = ckb_load_cell_data(cache, &_len, 0, i, CKB_SOURCE_OUTPUT);
            if (ret != CKB_SUCCESS || _len > 0)
            {
                return ERROR_NO_PERONSAL_NO_DATA;
            }
            mol_seg_t empty = {NULL, 0};
            mol_seg_t callback_cache = {cache, len};
            CHECK_RET(callback->call(
                callback->args, i, callback_cache, personal_owner, empty, callback->herr));
            continue;
        }
        if (ret != CKB_SUCCESS || _len > len)
        {
            return ERROR_LOADING_PERSONAL_CELL;
        }
        mol_seg_t script_seg = {cache, _len};
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
        mol_seg_t flag1_seg = {script_args_bytes_seg.ptr + 1, script_args_bytes_seg.size - 1};
        if (MolReader_Flag_1_verify(&flag1_seg, false) != MOL_OK)
        {
            return ERROR_FLAG_1_BYTES;
        }
        // non-burned cell
        _len = len;
        ret = ckb_load_cell_data(cache, &_len, 0, i, CKB_SOURCE_OUTPUT);
        if (ret != CKB_SUCCESS || _len > len)
        {
            return ERROR_LOADING_PERSONAL_CELL;
        }
        mol_seg_t data = {cache, _len};
        mol_seg_t callback_cache = {cache + _len, len - _len};
        CHECK_RET(callback->call(
            callback->args, i, callback_cache, personal_owner, data, callback->herr));
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
            if (which)
            {
                *which = -1;
            }
            break;
        }
        else if (ret == CKB_ITEM_MISSING)
        {
            continue;
        }
        else if (ret != CKB_SUCCESS || len != HASH_SIZE)
        {
            return ERROR_NO_DEPLOYMENT_CELL;
        }
        if (memcmp(type_hash, expected_hash, HASH_SIZE) == 0)
        {
            if (which)
            {
                *which = i;
            }
            break;
        }
    }
    return CKB_SUCCESS;
}

int ckbx_check_request_exist(
    uint8_t *cache, size_t len, size_t source, size_t i, uint8_t expected_project_id[HASH_SIZE],
    mol_seg_t *output_request_seg)
{
    int ret = ckb_load_cell_by_field(cache, &len, 0, i, source, CKB_CELL_FIELD_LOCK);
    if (ret != CKB_SUCCESS || len > MAX_CACHE_SIZE)
    {
        return ERROR_NO_REQUEST_CELLS;
    }
    mol_seg_t script_seg = {cache, len};
    mol_seg_t script_args_seg = MolReader_Script_get_args(&script_seg);
    mol_seg_t script_args_bytes_seg = MolReader_Bytes_raw_bytes(&script_args_seg);
    if (script_args_bytes_seg.size < 1 || script_args_bytes_seg.ptr[0] != FLAG_REQUEST)
    {
        return ERROR_REQUEST_ARGS;
    }
    uint8_t project_id[HASH_SIZE];
    CHECK_RET(ckbx_flag2_load_project_id(
        script_args_bytes_seg.ptr + 1, script_args_bytes_seg.size - 1, project_id));
    if (memcmp(expected_project_id, project_id, HASH_SIZE))
    {
        return ERROR_REQUEST_ARGS;
    }
    if (output_request_seg)
    {
        len = MAX_CACHE_SIZE;
        ret = ckb_load_cell_data(cache, &len, 0, i, source);
        if (ret != CKB_SUCCESS || len > MAX_CACHE_SIZE)
        {
            return ERROR_REQUEST_ARGS;
        }
        mol_seg_t request_seg = {cache, len};
        *output_request_seg = request_seg;
    }
    return CKB_SUCCESS;
}

int ckbx_check_personal_exist(
    uint8_t *cache, size_t len, size_t source, size_t i, uint8_t expected_project_id[HASH_SIZE])
{
    int ret = ckb_load_cell_by_field(cache, &len, 0, i, source, CKB_CELL_FIELD_TYPE);
    if (ret == CKB_INDEX_OUT_OF_BOUND)
    {
        return CKB_SUCCESS;
    }
    if (ret != CKB_SUCCESS || len > MAX_CACHE_SIZE)
    {
        return ERROR_LOADING_PERSONAL_CELL;
    }
    mol_seg_t script_seg = {cache, len};
    mol_seg_t script_args_seg = MolReader_Script_get_args(&script_seg);
    mol_seg_t script_args_bytes_seg = MolReader_Bytes_raw_bytes(&script_args_seg);
    if (script_args_bytes_seg.size < 1 || script_args_bytes_seg.ptr[0] != FLAG_PERSONAL)
    {
        return ERROR_PERSONAL_ARGS;
    }
    uint8_t project_id[HASH_SIZE];
    CHECK_RET(ckbx_flag1_load_project_id(
        script_args_bytes_seg.ptr + 1, script_args_bytes_seg.size - 1, project_id));
    if (memcmp(expected_project_id, project_id, HASH_SIZE))
    {
        return ERROR_PERSONAL_ARGS;
    }
    return CKB_SUCCESS;
}

int ckbx_check_global_exist(
    uint8_t *cache, size_t len, size_t source, uint8_t expected_project_id[HASH_SIZE],
    uint8_t expected_code_hash[HASH_SIZE], mol_seg_t *global_data, uint8_t global_driver[HASH_SIZE])
{
    int ret = ckb_load_cell_by_field(cache, &len, 0, 0, source, CKB_CELL_FIELD_TYPE);
    if (ret != CKB_SUCCESS || len > MAX_CACHE_SIZE)
    {
        return ERROR_LOADING_GLOBAL_CELL;
    }
    mol_seg_t script_seg = {cache, len};
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
        script_args_bytes_seg.ptr + 1, script_args_bytes_seg.size - 1, project_id));
    if (memcmp(expected_project_id, project_id, HASH_SIZE))
    {
        return ERROR_GLOBAL_ARGS;
    }
    // dump global cell data
    len = MAX_CACHE_SIZE;
    ret = ckb_load_cell_data(cache, &len, 0, 0, source);
    if (ret != CKB_SUCCESS || len > MAX_CACHE_SIZE)
    {
        return ERROR_LOADING_GLOBAL_CELL;
    }
    mol_seg_t data = {cache, len};
    *global_data = data;
    // dump global lock script_hash
    len = HASH_SIZE;
    ret = ckb_load_cell_by_field(global_driver, &len, 0, 0, source, CKB_CELL_FIELD_LOCK_HASH);
    if (ret != CKB_SUCCESS)
    {
        return ERROR_LOADING_GLOBAL_CELL;
    }
    return CKB_SUCCESS;
}

// int ckbx_check_request_hash_exist(
//     size_t source, uint8_t expected_hash[HASH_SIZE], size_t indices[MAX_SAME_REQUEST_COUNT])
// {
//     uint8_t lock_hash[HASH_SIZE];
//     uint64_t len = HASH_SIZE;
//     // valid offset of request lock_hash starts from 1, so fully ZERO means NOT-FOUND for indices
//     memset(indices, 0, sizeof(size_t) * MAX_SAME_REQUEST_COUNT);
//     size_t j = 0;
//     for (size_t i = 1; true; ++i)
//     {
//         int ret = ckb_load_cell_by_field(lock_hash, &len, 0, i, source, CKB_CELL_FIELD_LOCK_HASH);
//         if (ret == CKB_INDEX_OUT_OF_BOUND)
//         {
//             break;
//         }
//         if (ret != CKB_SUCCESS)
//         {
//             return ERROR_LOADING_SCRIPT;
//         }
//         if (memcmp(lock_hash, expected_hash, HASH_SIZE) == 0)
//         {
//             if (j >= MAX_SAME_REQUEST_COUNT)
//             {
//                 return ERROR_REQUEST_EXCESSIVE;
//             }
//             indices[j++] = i;
//         }
//     }
//     size_t empty[MAX_SAME_REQUEST_COUNT] = {0};
//     if (memcmp(indices, empty, sizeof(empty)) == 0)
//     {
//         return ERROR_REQUEST_NOT_FOUND;
//     }
//     return CKB_SUCCESS;
// }

int ckbx_check_request_cells_validation(uint8_t *cache, size_t len, mol_seg_t cells_seg)
{
    if (!MolReader_CellVec_verify(&cells_seg, false))
    {
        return ERROR_REQUEST_CELLS_FORMAT;
    }
    size_t count = MolReader_CellVec_length(&cells_seg);
    for (size_t i = 0; i < count; ++i)
    {
        mol_seg_t cell_seg = MolReader_CellVec_get(&cells_seg, i).seg;
        mol_seg_t owner_lockscript_seg = MolReader_Cell_get_owner_lockscript(&cell_seg);
        mol_seg_t owner_lockscript_bytes_seg = MolReader_String_raw_bytes(&owner_lockscript_seg);
        size_t _len = len;
        int ret = ckb_load_cell_by_field(cache, &_len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK);
        if (ret != CKB_SUCCESS ||
            _len != owner_lockscript_bytes_seg.size ||
            memcmp(cache, owner_lockscript_bytes_seg.ptr, _len))
        {
            return ERROR_REQUEST_CELLS_LOCKSCRIPT;
        }
        mol_seg_t data_seg = MolReader_Cell_get_data(&cell_seg);
        _len = len;
        ret = ckb_load_cell_data(cache, &_len, 0, i, CKB_SOURCE_INPUT);
        if (MolReader_StringOpt_is_none(&data_seg))
        {
            if (ret != CKB_SUCCESS || _len != 0)
            {
                return ERROR_REQUEST_CELLS_DATA;
            }
        }
        else
        {
            mol_seg_t data_bytes_seg = MolReader_String_raw_bytes(&data_seg);
            if (ret != CKB_SUCCESS ||
                _len != data_bytes_seg.size ||
                memcmp(cache, data_bytes_seg.ptr, _len))
            {
                return ERROR_REQUEST_CELLS_DATA;
            }
        }
    }
    return CKB_SUCCESS;
}

int ckbx_check_function_celldep_exist(
    uint8_t *cache, size_t len, uint8_t expected_code_hash[HASH_SIZE],
    uint8_t expected_project_id[HASH_SIZE], uint8_t expected_celldep_lockhash[HASH_SIZE],
    mol_seg_t *celldep_data)
{
    uint8_t project_id[HASH_SIZE];
    for (size_t i = 0; true; ++i)
    {
        // check if lock_script hash is expected personal_lockhash
        size_t _len = len;
        int ret = ckb_load_cell_by_field(cache, &_len, 0, i, CKB_SOURCE_CELL_DEP, CKB_CELL_FIELD_LOCK_HASH);
        if (ret != CKB_SUCCESS || _len > len)
        {
            return ERROR_MISS_FUNCTION_CELLDEP;
        }
        if (memcmp(cache, expected_celldep_lockhash, HASH_SIZE))
        {
            continue;
        }
        // check if type_script matches code_hash and project_id
        _len = len;
        ret = ckb_load_cell_by_field(cache, &_len, 0, i, CKB_SOURCE_CELL_DEP, CKB_CELL_FIELD_TYPE);
        if (ret != CKB_SUCCESS || _len > len)
        {
            return ERROR_MISS_FUNCTION_CELLDEP;
        }
        mol_seg_t script_seg = {cache, _len};
        mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
        if (memcmp(expected_code_hash, code_hash_seg.ptr, HASH_SIZE))
        {
            return ERROR_MISS_FUNCTION_CELLDEP;
        }
        mol_seg_t script_args_seg = MolReader_Script_get_args(&script_seg);
        mol_seg_t script_args_bytes_seg = MolReader_Bytes_raw_bytes(&script_args_seg);
        if (script_args_bytes_seg.size < 1 || script_args_bytes_seg.ptr[0] != FLAG_PERSONAL)
        {
            return ERROR_MISS_FUNCTION_CELLDEP;
        }
        CHECK_RET(ckbx_flag1_load_project_id(
            script_args_bytes_seg.ptr + 1, script_args_bytes_seg.size - 1, project_id));
        if (memcmp(expected_project_id, project_id, HASH_SIZE))
        {
            return ERROR_MISS_FUNCTION_CELLDEP;
        }
        if (celldep_data)
        {
            _len = len;
            ret = ckb_load_cell_data(cache, &_len, 0, i, CKB_SOURCE_CELL_DEP);
            if (ret != CKB_SUCCESS || _len > len)
            {
                return ERROR_MISS_FUNCTION_CELLDEP;
            }
            celldep_data->ptr = cache;
            celldep_data->size = _len;
        }
        break;
    }
    return CKB_SUCCESS;
}

int ckbx_check_global_update_mode(uint8_t *cache, size_t len, bool *is_update)
{
    int ret = ckb_load_cell_data(cache, &len, 0, 0, CKB_SOURCE_GROUP_INPUT);
    if ((ret != CKB_SUCCESS && ret != CKB_INDEX_OUT_OF_BOUND) || len > MAX_CACHE_SIZE)
    {
        return ERROR_CHECK_GLOBAL_MODE;
    }
    *is_update = (ret == CKB_SUCCESS);
    return CKB_SUCCESS;
}

int ckbx_check_personal_update_mode(
    uint8_t *cache, size_t len, uint8_t code_hash[HASH_SIZE], bool *is_update)
{
    size_t _len = len;
    int ret = ckb_load_cell_by_field(cache, &_len, 0, 0, CKB_SOURCE_GROUP_INPUT, CKB_CELL_FIELD_CAPACITY);
    if (ret == CKB_INDEX_OUT_OF_BOUND)
    {
        *is_update = false;
        return CKB_SUCCESS;
    }
    else if (ret != CKB_SUCCESS)
    {
        return ERROR_CHECK_PERSONAL_MODE;
    }
    _len = len;
    ret = ckb_load_cell_by_field(cache, &_len, 0, 1, CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK);
    if (ret == CKB_INDEX_OUT_OF_BOUND)
    {
        *is_update = false;
        return CKB_SUCCESS;
    }
    else if (ret != CKB_SUCCESS)
    {
        return ERROR_CHECK_PERSONAL_MODE;
    }
    mol_seg_t script_seg = {cache, len};
    mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
    *is_update = (memcmp(code_hash, code_hash_seg.ptr, HASH_SIZE) == 0);
    return CKB_SUCCESS;
}

int ckbx_get_parallel_cell_capacity(
    size_t left_source, bool left_occupied, size_t right_source, bool right_occupied,
    size_t i, uint64_t *left_ckb, uint64_t *right_ckb)
{
    size_t len = sizeof(uint64_t);
    int ret = ckb_load_cell_by_field(
        left_ckb, &len, 0, i, left_source,
        left_occupied ? CKB_CELL_FIELD_OCCUPIED_CAPACITY : CKB_CELL_FIELD_CAPACITY);
    if (ret != CKB_SUCCESS || len != sizeof(uint64_t))
    {
        return ERROR_CHECK_PARALLEL_CKB;
    }
    ret = ckb_load_cell_by_field(
        right_ckb, &len, 0, i, right_source,
        right_occupied ? CKB_CELL_FIELD_OCCUPIED_CAPACITY : CKB_CELL_FIELD_CAPACITY);
    if (ret != CKB_SUCCESS || len != sizeof(uint64_t))
    {
        return ERROR_CHECK_PARALLEL_CKB;
    }
    return CKB_SUCCESS;
}

int ckbx_get_random_seeds(uint8_t *cache, size_t len, uint8_t seeds[HALF_HASH_SIZE])
{
    blake2b_state hasher;
    blake2b_init(&hasher, HALF_HASH_SIZE);
    int n = ckb_calculate_inputs_len();
    for (int i = 0; i < n; ++i)
    {
        size_t _len = len;
        int ret = ckb_load_input(cache, &_len, 0, i, CKB_SOURCE_INPUT);
        if (ret != CKB_SUCCESS)
        {
            return ERROR_CALCULATE_RANDOM;
        }
        blake2b_update(&hasher, cache, _len);
    }
    blake2b_final(&hasher, seeds, HALF_HASH_SIZE);
    return CKB_SUCCESS;
}

#endif