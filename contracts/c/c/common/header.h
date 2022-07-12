#ifndef CKB_LUA_HEADER
#define CKB_LUA_HEADER

#include <stdlib.h>
#include "ckb_syscalls.h"

#define bool int
#define true 1
#define false 0

#define CHECK_RET(x) \
    ret = x;         \
    if (ret != 0) {  \
        return ret;  \
    }

#define DEBUG_PRINT(s, ...)         \
    char debug[512];                \
    sprintf(debug, s, __VA_ARGS__); \
    ckb_debug(debug);

#define MAX_CACHE_SIZE (64 * 1024)
#define MAX_JSON_SIZE 1024
#define MAX_FUNCTION_CALL_SIZE 256
#define MAX_JSON_TOKEN_COUNT 64
#define HASH_SIZE 32
#define HASH_HEX_SIZE (HASH_SIZE * 2)
#define PREFIX "return "
#define CKB_ONE 100000000

enum FALG
{
    FLAG_GLOBAL,
    FLAG_PERSONAL,
    FLAG_REQUEST
};

enum ERROR
{
    ERROR_LOADING_SCRIPT = 4, 
    ERROR_LOADING_REQUEST_CELL,
    ERROR_LOADING_GLOBAL_CELL,
    ERROR_LOADING_PERSONAL_CELL,
    ERROR_LUA_INIT,
    ERROR_LUA_SCRIPT_ARGS,
    ERROR_GLOBAL_ARGS,
    ERROR_REQUEST_ARGS,
    ERROR_REQUEST_CALLER_HASH,
    ERROR_FLAG_0_BYTES,
    ERROR_FLAG_1_BYTES,
    ERROR_FLAG_2_BYTES,
    ERROR_NO_DEPLOYMENT_CELL,
    ERROR_DEPLOYMENT_FORMAT,
    ERROR_GLOBAL_DATA_FORMAT,
    ERROR_RUN_LUA_CODE,
    ERROR_CHECK_LUA_GLOBAL_DATA,
    ERROR_CHECK_LUA_PERSONAL_DATA,
    ERROR_REQUEST_FLAG,
    ERROR_UNCONTINUOUS_REQUEST,
    ERROR_APPLY_LUA_REQUEST,
    ERROR_TABLE_TO_SJON,
    ERROR_JSON_TO_TABLE,
    ERROR_UNINITIAL_CONTEXT,
};

#endif