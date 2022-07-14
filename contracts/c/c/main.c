#include "entry.c"

int contract_error_handler(lua_State *L)
{
    const char *error = lua_tostring(L, -1);
    ckb_debug(error);
    return 0;
}

int main()
{
    // init lua status (or context)
    lua_State *L = luaL_newstate(0, 0);

    // load error handler for contract error print
    lua_pushcfunction(L, contract_error_handler);
    int herr = lua_gettop(L);

	int ret = CKB_SUCCESS;
	CHECK_RET(lua_init(L, herr));
	CHECK_RET(lua_verify(L, herr));

    return ret;
}
