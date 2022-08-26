#ifndef CKB_LUA_WRAPPER
#define CKB_LUA_WRAPPER

#include "lua_json.h"

typedef int (*LuaFunc)(lua_State *);

typedef struct
{
    const char *name;
    LuaFunc callback;
} LuaOperation;

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

void _strcat_table_key_value(lua_State *L, char *buffer, int size, int index, int is_key)
{
    if (is_key)
    {
        strncat(buffer, "[", size);
    }
    if (lua_isinteger(L, index))
    {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "%lld", lua_tointeger(L, index));
        strncat(buffer, tmp, size);
    }
    else if (lua_isnumber(L, index))
    {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "%f", lua_tonumber(L, index));
        strncat(buffer, tmp, size);
    }
    else if (lua_isstring(L, index))
    {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "\"%s\"", lua_tostring(L, index));
        strncat(buffer, tmp, size);
    }
    else if (lua_isboolean(L, index))
    {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "%s", lua_toboolean(L, index) ? "true" : "false");
        strncat(buffer, tmp, size);
    }
    if (is_key)
    {
        strncat(buffer, "] => ", size);
    }
}

void _print_table(lua_State *L, int tbl_index, char *prefix, int prefix_len)
{
    lua_pushnil(L);
    while (lua_next(L, tbl_index))
    {
        char buffer[512] = "";
        prefix[prefix_len] = '\0';
        lua_pushvalue(L, -2);
        strncat(buffer, prefix, sizeof(buffer) - 1);
        _strcat_table_key_value(L, buffer, sizeof(buffer) - 1, -1, true);
        if (lua_istable(L, -2))
        {
            strcat(prefix, "  ");
            ckb_debug(buffer);
            _print_table(L, lua_gettop(L) - 1, prefix, strlen(prefix));
        }
        else
        {
            _strcat_table_key_value(L, buffer, sizeof(buffer) - 1, -2, false);
            ckb_debug(buffer);
        }
        lua_pop(L, 2);
    }
}

int lua_println(lua_State *L)
{
    for (int i = 1; i <= lua_gettop(L); ++i)
    {
        if (lua_isstring(L, i))
        {
            ckb_debug(lua_tostring(L, i));
        }
        else if (lua_istable(L, i))
        {
            char prefix[256] = "";
            ckb_debug("--------------TABLE PRINT START--------------");
            _print_table(L, i, prefix, 0);
            ckb_debug("--------------TABLE PRINT CLOSE--------------");
        }
        else if (lua_isinteger(L, i))
        {
            char buffer[256];
            snprintf(buffer, sizeof(buffer), "%lld", lua_tointeger(L, i));
            ckb_debug(buffer);
        }
        else if (lua_isnumber(L, i))
        {
            char buffer[256];
            snprintf(buffer, sizeof(buffer), "%f", lua_tonumber(L, i));
            ckb_debug(buffer);
        }
    }
    return 0;
}

int lua_load_project_code(lua_State *L, uint8_t *code, size_t len, int herr)
{
    if (luaL_loadbuffer(L, (const char *)code, len, "luavm") || lua_pcall(L, 0, 0, herr))
    {
        char debug[256];
        sprintf(debug, "invalid lua script, length = %lu", len);
        ckb_debug(debug);
        return ERROR_RUN_LUA_CODE;
    }
    return CKB_SUCCESS;
}

int lua_inject_json_context(lua_State *L, uint8_t *json_data, size_t len, const char *name)
{
    if (len == 0 || json_data == NULL)
    {
        return CKB_SUCCESS;
    }
    // check `msg` or make new one
    lua_getglobal(L, "msg");
    if (!lua_istable(L, -1))
    {
        lua_newtable(L);
    }
    // create Global table
    int ret = CKB_SUCCESS;
    CHECK_RET(_json_to_table(L, (char *)json_data, len, NULL));
    lua_setfield(L, -2, name);
    // setup `msg`
    lua_setglobal(L, "msg");
    return CKB_SUCCESS;
}

int lua_inject_auth_context(lua_State *L, uint8_t auth_hash[HASH_SIZE], const char *name)
{
    // check `msg` or make new one
    lua_getglobal(L, "msg");
    if (!lua_istable(L, -1))
    {
        lua_newtable(L);
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

int lua_inject_operation_context(lua_State *L, LuaOperation *operations, size_t len)
{
    // check `msg` or make new one
    lua_getglobal(L, "msg");
    if (!lua_istable(L, -1))
    {
        lua_newtable(L);
    }
    // push functions
    for (size_t i = 0; i < len; ++i)
    {
        lua_pushcfunction(L, operations[i].callback);
        lua_setfield(L, -2, operations[i].name);
    }
    // reset `msg`
    lua_setglobal(L, "msg");
    return CKB_SUCCESS;
}

int lua_inject_random_seeds(lua_State *L, uint64_t seed[2], int herr)
{
    lua_getglobal(L, "math");
    lua_pushstring(L, "randomseed");
    lua_gettable(L, -2);
    lua_pushinteger(L, seed[0]);
    lua_pushinteger(L, seed[1]);
    if (lua_pcall(L, 2, 0, herr))
    {
        ckb_debug("[ERROR] invalid math.randomseed params.");
        return ERROR_LUA_INJECT;
    }
    return CKB_SUCCESS;
}

int lua_check_global_data(lua_State *L, const char *method, uint8_t *expected_json, size_t len, int herr)
{
    // load compare function
    lua_getglobal(L, "_compare_tables");
    // load first table parameter
    if (luaL_loadstring(L, method) || lua_pcall(L, 0, 1, herr))
    {
        ckb_debug("[ERROR] invalid global checker method.");
        return ERROR_CHECK_LUA_GLOBAL_DATA;
    }
    // global data must be table
    if (!lua_istable(L, -1))
    {
        return ERROR_CHECK_LUA_GLOBAL_DATA;
    }
    int ret = CKB_SUCCESS;
    // load second table parameter
    CHECK_RET(_json_to_table(L, (char *)expected_json, len, NULL));
    // call to compare two tables
    lua_pcall(L, 2, 1, herr);
    if (!lua_toboolean(L, -1))
    {
        return ERROR_CHECK_LUA_GLOBAL_DATA;
    }
    return CKB_SUCCESS;
}

int lua_check_personal_data(
    lua_State *L, const char *method, uint8_t *owner, size_t owner_len, uint8_t *data, size_t data_len, int herr)
{
    // load compare function
    lua_getglobal(L, "_compare_tables");
    // load first table parameter
    if (luaL_loadstring(L, method) || lua_pcall(L, 0, 1, herr))
    {
        ckb_debug("[ERROR] invalid personal checker method.");
        return ERROR_CHECK_LUA_PERSONAL_DATA;
    }
    // personal data must be table
    if (!lua_istable(L, -1))
    {
        return ERROR_CHECK_LUA_PERSONAL_DATA;
    }
    int ret = CKB_SUCCESS;
    // create data table for comparision
    lua_newtable(L);
    char hex[owner_len * 2];
    _to_hex(hex, owner, owner_len);
    lua_pushlstring(L, hex, owner_len * 2);
    lua_setfield(L, -2, "owner");
    if (data != NULL)
    {
        if (data_len > 0)
        {
            CHECK_RET(_json_to_table(L, (char *)data, data_len, NULL));
        }
        else
        {
            lua_newtable(L);
        }
        lua_setfield(L, -2, "data");
    }
    // compare with unchecked table
    lua_pcall(L, 2, 1, herr);
    if (!lua_toboolean(L, -1))
    {
        return ERROR_CHECK_LUA_PERSONAL_DATA;
    }
    return CKB_SUCCESS;
}

#endif