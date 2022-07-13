#include "verifier/flag_global.h"
#include "verifier/flag_personal.h"
#include "verifier/flag_request.h"

int lua_init(lua_State *L, int herr)
{
    luaL_openlibs(L);
    lua_register(L, "print", lua_println);

    const char *table_checker_chunck = " \
        function _compare_tables(tab1, tab2) \
            for k, v in pairs(tab1) do \
                if type(v) == 'table' then \
                    if type(tab2[k]) ~= 'table' or _compare_tables(v, tab2[k]) == false then \
                        return false \
                    end \
                elseif v ~= tab2[k] then \
                    return false \
                end \
            end \
            for k, _ in pairs(tab2) do \
                if tab1[k] == nil then \
                    return false \
                end \
            end \
            return true \
        end \
    ";
    if (luaL_loadstring(L, table_checker_chunck) || lua_pcall(L, 0, 0, herr))
    {
        ckb_debug("[ERROR] invalid table checker chunck.");
        return ERROR_LUA_INIT;
    }

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
            CHECK_RET(inject_personal_operation(L));
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
