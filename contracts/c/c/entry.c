#include "verifier/flag_global.h"
#include "verifier/flag_personal.h"
#include "verifier/flag_request.h"

int lua_init(lua_State *L, int herr)
{
    luaL_openlibs(L);
    lua_register(L, "print", lua_println);

    /*
        function _compare_tables(tab1, tab2)
            for k, v in pairs(tab1) do
                if type(v) == 'table' then
                    if type(tab2[k]) ~= 'table' or _compare_tables(v, tab2[k]) == false then
                        return false
                    end
                elseif v ~= tab2[k] then
                    return false
                end
            end
            for k, _ in pairs(tab2) do
                if tab1[k] == nil then
                    return false
                end
            end
            return true
        end
        function _deep_copy(tab)
            if type(tab) ~= 'table' then
                return tab
            end
            local new_tab = {}
            for k, v in pairs(tab) do
                new_tab[k] = _deep_copy(v)
            end
            return new_tab
        end
    */
    char table_utility_chunck[] = {
        27, 76, 117, 97, 84, 0, 25, 147, 13, 10, 26, 10, 4, 8, 8, 120, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 40, 119, 64, 1, 128, 128, 128, 0, 1, 2, 134, 81, 0, 0, 0, 79, 0, 0, 0, 15, 0, 0, 0, 79, 128,
        0, 0, 15, 0, 1, 0, 70, 0, 1, 1, 130, 4, 144, 95, 99, 111, 109, 112, 97, 114, 101, 95, 116, 97, 98,
        108, 101, 115, 4, 139, 95, 100, 101, 101, 112, 95, 99, 111, 112, 121, 129, 1, 0, 0, 130, 128, 129,
        145, 2, 0, 11, 174, 11, 1, 0, 0, 128, 1, 0, 0, 68, 1, 2, 5, 75, 1, 12, 0, 11, 4, 0, 1, 128, 4, 7,
        0, 68, 4, 2, 2, 60, 4, 2, 0, 184, 6, 0, 128, 11, 4, 0, 1, 140, 4, 1, 6, 68, 4, 2, 2, 60, 4, 2, 0,
        184, 2, 0, 128, 11, 4, 0, 3, 128, 4, 7, 0, 12, 5, 1, 6, 68, 4, 3, 2, 60, 4, 4, 0, 184, 3, 0, 128,
        5, 4, 0, 0, 70, 132, 2, 0, 56, 2, 0, 128, 12, 4, 1, 6, 185, 131, 8, 0, 184, 0, 0, 128, 5, 4, 0, 0,
        70, 132, 2, 0, 76, 1, 0, 2, 77, 1, 13, 0, 54, 1, 0, 0, 11, 1, 0, 0, 128, 1, 1, 0, 68, 1, 2, 5, 75,
        129, 2, 0, 12, 4, 0, 6, 60, 4, 5, 0, 184, 0, 0, 128, 5, 4, 0, 0, 70, 132, 2, 0, 76, 1, 0, 2, 77, 129,
        3, 0, 54, 1, 0, 0, 7, 1, 0, 0, 70, 129, 2, 0, 70, 129, 1, 0, 134, 4, 134, 112, 97, 105, 114, 115, 4,
        133, 116, 121, 112, 101, 4, 134, 116, 97, 98, 108, 101, 4, 144, 95, 99, 111, 109, 112, 97, 114, 101,
        95, 116, 97, 98, 108, 101, 115, 1, 0, 129, 0, 0, 0, 128, 128, 128, 128, 128, 128, 146, 155, 1, 0, 10,
        149, 139, 0, 0, 0, 0, 1, 0, 0, 196, 0, 2, 2, 188, 128, 1, 0, 56, 0, 0, 128, 70, 128, 2, 0, 147, 0, 0,
        0, 82, 0, 0, 0, 11, 1, 0, 2, 128, 1, 0, 0, 68, 1, 2, 5, 75, 1, 2, 0, 11, 4, 0, 3, 128, 4, 7, 0, 68, 4,
        2, 2, 144, 0, 6, 8, 76, 1, 0, 2, 77, 1, 3, 0, 54, 1, 0, 0, 198, 128, 2, 0, 70, 129, 1, 0, 132, 4, 133,
        116, 121, 112, 101, 4, 134, 116, 97, 98, 108, 101, 4, 134, 112, 97, 105, 114, 115, 4, 139, 95, 100,
        101, 101, 112, 95, 99, 111, 112, 121, 129, 0, 0, 0, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    if (luaL_loadbuffer(L, table_utility_chunck, 475, "utility") || lua_pcall(L, 0, 0, herr))
    {
        ckb_debug("[ERROR] invalid table utility chunck.");
        return ERROR_LUA_INJECT;
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
