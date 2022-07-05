#ifndef CKB_LUA_WRAPPER
#define CKB_LUA_WRAPPER

#include "lua_json.h"

void _to_hex(char *hex, uint8_t *bytes, int size)
{
	int pointer = 0;
	char hex_char[16];
	for (int i = 0; i < size; ++i)
	{
		sprintf(hex_char, "%02x", (int)bytes[i]);
		memcpy(&hex[pointer], hex_char, strlen(hex_char));
		pointer += strlen(hex_char);
	}
}

int lua_load_project_code(lua_State *L, uint8_t *code, size_t len, int herr)
{
    if (luaL_loadbuffer(L, (const char *) code, len, "luavm") || lua_pcall(L, 0, 0, herr))
    {
        char debug[256];
        sprintf(debug, "invalid lua script, length = %lu", len);
        ckb_debug(debug);
        return ERROR_RUN_LUA_CODE;
    }
    return CKB_SUCCESS;
}

int lua_inject_global_context(lua_State *L, char *global_json)
{
    // create CONTEXT table
    lua_newtable(L);
    // create Global table
    int ret = CKB_SUCCESS;
    CHECK_RET(_json_to_table(L, global_json));
    lua_setfield(L, -2, "global");
    // setup `msg`
    lua_setglobal(L, "msg");
    return CKB_SUCCESS;
}

int lua_inject_auth_context(lua_State *L, uint8_t auth_hash[HASH_SIZE], const char *name)
{
    // check `msg`
    lua_getglobal(L, "msg");
    if (!lua_istable(L, -1))
    {
        return ERROR_UNINITIAL_CONTEXT;
    }
    // push lock hash
    char hex[HASH_HEX_SIZE];
    _to_hex(hex, auth_hash, HASH_SIZE);
    lua_pushlstring(L, hex, HASH_HEX_SIZE);
    lua_setfield(L, -2, name);
    // reset `msg`
    lua_setglobal(L, "msg");
    return CKB_SUCCESS;
}

int lua_check_global_data(lua_State *L, const char *method, uint8_t *expected_json, size_t len, int herr)
{
    // load compare function
    lua_getglobal(L, "_compare_tables");
    // load first table parameter
    if (luaL_loadstring(L, method) || lua_pcall(L, 0, 1, herr))
    {
        ckb_debug("invalid update method.");
        return ERROR_CHECK_LUA_GLOBAL_DATA;
    }
    // global data must be table
    if (!lua_istable(L, -1))
    {
        return ERROR_CHECK_LUA_GLOBAL_DATA;
    }
    int ret = CKB_SUCCESS;
    expected_json[len] = '\0';
    // load second table parameter
    CHECK_RET(_json_to_table(L, (char *)expected_json));
    // call to compare two tables
    lua_pcall(L, 2, 1, herr);
    if (lua_toboolean(L, -1))
    {
        return ERROR_CHECK_LUA_GLOBAL_DATA;
    }
    return CKB_SUCCESS;
}

#endif