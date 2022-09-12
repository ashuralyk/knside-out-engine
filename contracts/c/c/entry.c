#include "verifier/flag_global.h"
#include "verifier/flag_personal.h"
#include "verifier/flag_request.h"

int lua_init(lua_State *L, int herr)
{
    luaL_openlibs(L);
    lua_register(L, "print", lua_println);
    return CKB_SUCCESS;
}

int lua_verify(lua_State *L, int herr)
{
    // Fetch ckb script from context and point to "args" field
    uint8_t cache[MAX_CACHE_SIZE];
    uint8_t code_hash[HASH_SIZE];
    mol_seg_t script_args;
    int ret = CKB_SUCCESS;
    CHECK_RET(ckbx_load_script(cache, MAX_CACHE_SIZE, &script_args, code_hash));

    // Get flag from args and dipatch handler
    uint8_t flag = script_args.ptr[0];
    switch (flag)
    {
    // represent global data
    case FLAG_GLOBAL:
    {
        CHECK_RET(verify_global_data(cache, L, herr, script_args, code_hash));
        break;
    }
    // represent personal data
    case FLAG_PERSONAL:
    {
        CHECK_RET(inject_personal_operation(cache, L, herr));
        CHECK_RET(verify_personal_data(cache, L, herr, script_args, code_hash));
        break;
    }
    // represent request data
    case FLAG_REQUEST:
    {
        CHECK_RET(verify_request_data(cache, L, herr, script_args, code_hash));
        break;
    }
    }

    return CKB_SUCCESS;
}
