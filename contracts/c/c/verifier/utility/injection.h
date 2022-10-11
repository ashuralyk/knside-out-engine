#ifndef CKB_LUA_INJECTIONS
#define CKB_LUA_INJECTIONS

#include "../../common/header.h"
#include "../../common/lua_wrap.h"
#include "../../common/high_level.h"

int _check_parallel_capacity(lua_State *L, size_t source, const char *key, const char *command)
{
    uint64_t ckb = (size_t)(luaL_checknumber(L, -1) * CKB_ONE);
    lua_getglobal(L, key);
    size_t i = lua_tointeger(L, -1);
    uint64_t offerred_ckb, occupied_ckb;
    int ret = ckbx_get_parallel_cell_capacity(
        source, false, i, source, true, i, &offerred_ckb, &occupied_ckb);
    if (ret != CKB_SUCCESS)
    {
        lua_pushboolean(L, false);
        return 1;
    }
    if (offerred_ckb < occupied_ckb + ckb)
    {
        DEBUG_PRINT(
            "[ERROR] %s: need more%4.f ckb. (cell = %lu)",
            command, (occupied_ckb + ckb - offerred_ckb) / (double)CKB_ONE, i);
        lua_pushboolean(L, false);
        return 1;
    }
    lua_pushboolean(L, true);
    return 1;
}

int lua_ckb_withdraw(lua_State *L)
{
    return _check_parallel_capacity(L, CKB_SOURCE_OUTPUT, LUA_OUTPUT_OFFSET, "withdraw");
}

int lua_ckb_deposit(lua_State *L)
{
    return _check_parallel_capacity(L, CKB_SOURCE_INPUT, LUA_INPUT_OFFSET, "deposit");
}

#endif