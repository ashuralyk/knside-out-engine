#ifndef CKB_LUA_WRAPPER
#define CKB_LUA_WRAPPER

#include "lua_json.h"

typedef int (*LuaFunc)(lua_State *);

typedef struct
{
    const char *name;
    LuaFunc callback;
} LuaOperation;

typedef struct
{
    lua_State *L;
    uint8_t *project_id;
    uint8_t *code_hash;
} LuaParams;

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

void lua_pushhexstrng(lua_State *L, uint8_t *hex_string, size_t len)
{
    char hex[len * 2];
    _to_hex(hex, hex_string, len);
    lua_pushlstring(L, hex, len * 2);
}

void lua_addoffset(lua_State *L, const char *offset, int change)
{
    lua_getglobal(L, offset);
    lua_pushinteger(L, lua_tointeger(L, -1) + change);
    lua_setglobal(L, offset);
    lua_pop(L, 1);
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

int lua_compare_two_tables(lua_State *L, bool *is_equal)
{
    int ret = CKB_SUCCESS;
    int tab1_i = lua_gettop(L) - 1;
    int tab2_i = tab1_i + 1;
    if (!lua_istable(L, tab1_i) || !lua_istable(L, tab2_i))
    {
        return ERROR_LUA_COMPARE_TABLE;
    }
    *is_equal = true;
    // start tranverse of table 1
    lua_pushnil(L);
    while (lua_next(L, tab1_i))
    {
        lua_pushvalue(L, -2);
        lua_gettable(L, tab2_i);
        if (lua_istable(L, -1) && lua_istable(L, -2))
        {
            CHECK_RET(lua_compare_two_tables(L, is_equal));
            if (*is_equal == false)
            {
                lua_settop(L, tab1_i - 1);
                return CKB_SUCCESS;
            }
        }
        else
        {
            if (!lua_compare(L, -1, -2, LUA_OPEQ))
            {
                *is_equal = false;
                lua_settop(L, tab1_i - 1);
                return CKB_SUCCESS;
            }
            lua_pop(L, 2);
        }
    }
    // start tranverse of table 2
    lua_pushnil(L);
    while (lua_next(L, tab2_i))
    {
        lua_pop(L, 1);
        lua_pushvalue(L, -1);
        lua_gettable(L, tab1_i);
        if (lua_isnil(L, -1))
        {
            *is_equal = false;
            lua_settop(L, tab1_i - 1);
            return CKB_SUCCESS;
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 2);
    return CKB_SUCCESS;
}

int lua_load_project_code(lua_State *L, uint8_t *code, size_t len, int herr)
{
    if (luaL_loadbuffer(L, (const char *)code, len, "luavm") || lua_pcall(L, 0, 0, herr))
    {
        DEBUG_PRINT("invalid lua script, length = %lu", len);
        return ERROR_RUN_LUA_CODE;
    }
    return CKB_SUCCESS;
}

int lua_inject_json_context(lua_State *L, uint8_t *json_data, size_t len, const char *name)
{
    // check `KOC` or make new one
    lua_getglobal(L, LUA_KOC);
    if (!lua_istable(L, -1))
    {
        lua_newtable(L);
    }
    // create Global table
    int ret = CKB_SUCCESS;
    if (len == 0 || json_data == NULL)
    {
        lua_pushnil(L);
    }
    else
    {
        CHECK_RET(_json_to_table(L, (char *)json_data, len, NULL));
    }
    lua_setfield(L, -2, name);
    // setup `KOC`
    lua_setglobal(L, LUA_KOC);
    return CKB_SUCCESS;
}

int lua_inject_auth_context(lua_State *L, uint8_t auth_hash[HASH_SIZE], const char *name)
{
    // check `KOC` or make new one
    lua_getglobal(L, LUA_KOC);
    if (!lua_istable(L, -1))
    {
        lua_newtable(L);
    }
    // push lock hash
    lua_pushhexstrng(L, auth_hash, HASH_SIZE);
    lua_setfield(L, -2, name);
    // reset `KOC`
    lua_setglobal(L, LUA_KOC);
    return CKB_SUCCESS;
}

int lua_inject_operation_context(lua_State *L, LuaOperation *operations, size_t len)
{
    // check `KOC` or make new one
    lua_getglobal(L, LUA_KOC);
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
    // reset `KOC`
    lua_setglobal(L, LUA_KOC);
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

int lua_check_global_data(lua_State *L, const char *method, mol_seg_t driver, mol_seg_t json, int herr)
{
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
    // load second table parameter
    lua_newtable(L);
    // fill `driver` object
    lua_pushhexstrng(L, driver.ptr, driver.size);
    lua_setfield(L, -2, "driver");
    // fill `global` object
    int ret = CKB_SUCCESS;
    CHECK_RET(_json_to_table(L, (char *)json.ptr, json.size, NULL));
    lua_setfield(L, -2, "global");
    // call to compare two tables
    bool equal = true;
    CHECK_RET(lua_compare_two_tables(L, &equal));
    if (!equal)
    {
        return ERROR_CHECK_LUA_GLOBAL_DATA;
    }
    return CKB_SUCCESS;
}

int lua_check_personal_data(lua_State *L, const char *method, mol_seg_t owner, mol_seg_t data, int herr)
{
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
    // create data table for comparision
    lua_newtable(L);
    // fill `owner` object
    lua_pushhexstrng(L, owner.ptr, owner.size);
    lua_setfield(L, -2, "owner");
    // fill `data` object
    if (data.ptr != NULL)
    {
        if (data.size > 0)
        {
            int ret = CKB_SUCCESS;
            CHECK_RET(_json_to_table(L, (char *)data.ptr, data.size, NULL));
        }
        else
        {
            lua_newtable(L);
        }
        lua_setfield(L, -2, "data");
    }
    // compare with unchecked table
    bool equal = true;
    int ret = CKB_SUCCESS;
    CHECK_RET(lua_compare_two_tables(L, &equal));
    if (!equal)
    {
        return ERROR_CHECK_LUA_PERSONAL_DATA;
    }
    return CKB_SUCCESS;
}

int lua_append_table(lua_State *L, int source, int target)
{
    if (!lua_istable(L, source) || !lua_istable(L, target))
    {
        return ERROR_LUA_TABLE_MERGE;
    }
    size_t offset = luaL_len(L, target);
    size_t size = luaL_len(L, source);
    for (size_t i = 1; i <= size; ++i)
    {
        lua_rawgeti(L, source, i);
        lua_rawseti(L, target, ++offset);
    }
    return CKB_SUCCESS;
}

int lua_deep_copy_table(lua_State *L)
{
    if (!lua_istable(L, -1))
    {
        return ERROR_LUA_DEEP_COPY;
    }
    int real_i = lua_gettop(L);
    lua_newtable(L);
    int copy_i = lua_gettop(L);
    // start tranverse
    lua_pushnil(L);
    while (lua_next(L, real_i))
    {
        if (lua_istable(L, -1))
        {
            lua_deep_copy_table(L);
            lua_pushvalue(L, -3);
            lua_pushvalue(L, -2);
            lua_settable(L, copy_i);
            lua_pop(L, 2);
        }
        else
        {
            lua_pushvalue(L, -2);
            lua_pushvalue(L, -2);
            lua_settable(L, copy_i);
            lua_pop(L, 1);
        }
    }
    return CKB_SUCCESS;
}

#endif