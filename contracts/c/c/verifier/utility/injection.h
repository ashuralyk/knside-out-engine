#ifndef CKB_LUA_INJECTIONS
#define CKB_LUA_INJECTIONS

#include "../../common/header.h"
#include "../../common/lua_wrap.h"
#include "../../common/high_level.h"

int _check_parallel_capacity(lua_State *L, size_t source, const char *memo)
{
    uint64_t ckb = (size_t)(luaL_checknumber(L, -1) * CKB_ONE);
    lua_getglobal(L, LUA_UNCHECKED);
    size_t i = luaL_len(L, -1) + 1;
    uint64_t offerred_ckb, occupied_ckb;
    int ret = ckbx_get_parallel_cell_capacity(
        source, false, source, true, i, &offerred_ckb, &occupied_ckb);
    if (ret != CKB_SUCCESS)
    {
        lua_pushboolean(L, false);
        return 1;
    }
    if (offerred_ckb < occupied_ckb + ckb)
    {
        DEBUG_PRINT(
            "[ERROR] %s: need more %4.f ckb. (cell = %lu)",
            memo, (occupied_ckb + ckb - offerred_ckb) / (double)CKB_ONE, i);
        lua_pushboolean(L, false);
        return 1;
    }
    lua_pushboolean(L, true);
    return 1;
}

int lua_ckb_withdraw(lua_State *L)
{
    return _check_parallel_capacity(L, CKB_SOURCE_OUTPUT, "withdraw");
}

int lua_ckb_deposit(lua_State *L)
{
    return _check_parallel_capacity(L, CKB_SOURCE_INPUT, "deposit");
}

int lua_check_koc(lua_State *L)
{
    int top = lua_gettop(L);
    // check variables validation
    lua_getglobal(L, LUA_KOC);
    lua_getfield(L, -1, "user");
    if (!lua_isstring(L, -1) || strlen(lua_tostring(L, -1)) != HASH_HEX_SIZE)
    {
        luaL_error(L, "[ERROR] `user` in KOC must be type string with length of %d", HASH_HEX_SIZE);
    }
    lua_pop(L, 1);
    lua_getfield(L, -1, "driver");
    if (!lua_isstring(L, -1) || strlen(lua_tostring(L, -1)) != HASH_HEX_SIZE)
    {
        luaL_error(L, "[ERROR] `driver` in KOC must be type string with length of %d", HASH_HEX_SIZE);
    }
    lua_pop(L, 1);
    lua_getfield(L, -1, "global");
    if (!lua_istable(L, -1))
    {
        luaL_error(L, "[ERROR] `global` in KOC must be type table");
    }
    lua_pop(L, 1);
    // check constants validation
    lua_getglobal(L, LUA_KOC_BACKUP);
    if (lua_istable(L, -1))
    {
        const char *keys[] = {"ckb_deposit", "ckb_withdraw", "owner"};
        for (int i = 0; i < 3; ++i)
        {
            const char *key = keys[i];
            lua_getfield(L, -2, key);
            lua_getfield(L, -2, key);
            if (!lua_compare(L, -1, -2, LUA_OPEQ))
            {
                luaL_error(L, "[ERROR] `%s` in KOC must be constant", key);
            }
            lua_pop(L, 2);
        }
    }
    lua_settop(L, top);
    return 0;
}

#endif