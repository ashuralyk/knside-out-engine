#ifndef CKB_LUA_WRAPPER
#define CKB_LUA_WRAPPER

#include "lua_json.h"

int lua_load_project_code(lua_State *L, uint8_t *code, size_t len, int herr)
{
    if (luaL_loadbuffer(L, (const char *) code, len, "luavm") || lua_pcall(L, 0, 0, herr))
    {
        ckb_debug("invalid lua script.");
        return ERROR_RUN_LUA_CODE;
    }
    return CKB_SUCCESS;
}

int lua_inject_project_context(lua_State *L, char *global_json)
{
    // create CONTEXT table
    lua_newtable(L);
    // create Global table
    int ret = _json_to_table(L, global_json);
    if (ret != CKB_SUCCESS)
    {
        return ret;
    }
    lua_setfield(L, -2, "Global");
    lua_setglobal(L, "CONTEXT");
    return CKB_SUCCESS;
}

int lua_check_global_data(lua_State *L, const char *method, bool update, uint8_t *expected_data, size_t len, int herr)
{
    if (update == true)
    {
        if (luaL_loadstring(L, method) || lua_pcall(L, 0, 1, herr))
        {
            ckb_debug("invalid update method.");
            return ERROR_CHECK_LUA_GLOBAL_DATA;
        }
    }
    else
    {
        lua_getglobal(L, method);
        if (!lua_isfunction(L, -1) || lua_pcall(L, 0, 1, herr))
        {
            ckb_debug("invalid global data initial function.");
            return ERROR_CHECK_LUA_GLOBAL_DATA;
        }
    }
    // global data must be table
    if (!lua_istable(L, -1))
    {
        return ERROR_CHECK_LUA_GLOBAL_DATA;
    }
    // turn table into json-string and compare with the expected
    uint8_t json[MAX_JSON_SIZE];
    int ret = _table_to_json(L, -1, json, MAX_JSON_SIZE, 0);
    if (ret != CKB_SUCCESS)
    {
        return ret;
    }
    if (memcmp(expected_data, json, len) != 0)
    {
        return ERROR_CHECK_LUA_GLOBAL_DATA;
    }
    return CKB_SUCCESS;
}

#endif