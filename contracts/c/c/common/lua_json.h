#ifndef CKB_LUA_JSON
#define CKB_LUA_JSON

#include "header.h"
#include "jsmn.h"
#include "lauxlib.h"
#include "lualib.h"

int _json_to_table_internal_table(lua_State *, char *, jsmntok_t *, int);
int _json_to_table_internal_array(lua_State *, char *, jsmntok_t *, int);

int _json_to_table(lua_State *L, char *json, size_t len, int *out_count)
{
    // make sure the end of bytes is ZERO
    char previous_char = json[len];
    json[len] = '\0';
    ckb_debug(json);

    jsmn_parser parser;
    jsmntok_t tokens[MAX_JSON_TOKEN_COUNT];

    jsmn_init(&parser);
    int count = jsmn_parse(&parser, json, len, tokens, MAX_JSON_TOKEN_COUNT);
    int ttype = tokens[0].type;
    if (count < 1 || (ttype != JSMN_OBJECT && ttype != JSMN_ARRAY))
    {
        return ERROR_JSON_TO_TABLE;
    }
    if (out_count)
    {
        *out_count = count;
    }

    lua_newtable(L);
    int ret = CKB_SUCCESS;
    if (ttype == JSMN_OBJECT)
    {
        ret = _json_to_table_internal_table(L, json, tokens, count);
    }
    else
    {
        ret = _json_to_table_internal_array(L, json, tokens, count);
    }
    json[len] = previous_char;
    return ret;
}

void _json_handle_primitive_and_string(lua_State *L, char *json, jsmntok_t *tokens, int i)
{
    if (strncmp(json + tokens[i].start, "true", strlen("true")) == 0)
    {
        lua_pushboolean(L, true);
    }
    else if (strncmp(json + tokens[i].start, "false", strlen("false")) == 0)
    {
        lua_pushboolean(L, false);
    }
    else
    {
        int size = tokens[i].end - tokens[i].start;
        if (tokens[i].type == JSMN_STRING)
        {
            lua_pushlstring(L, json + tokens[i].start, size);
        }
        else
        {
            char value[size + 1];
            memcpy(value, json + tokens[i].start, size);
            value[size] = '\0';
            lua_pushnumber(L, atof(value));
        }
    }
}

int _json_to_table_internal_table(lua_State *L, char *json, jsmntok_t *tokens, int count)
{
    // iterate key/value pairs, first is key, second is value
    for (int i = 1; i < count; ++i)
    {
        int j = i + 1;
        switch (tokens[j].type)
        {
        case JSMN_PRIMITIVE:
        case JSMN_STRING:
        {
            _json_handle_primitive_and_string(L, json, tokens, j);
            char old_char = json[tokens[i].end];
            json[tokens[i].end] = '\0';
            lua_setfield(L, -2, json + tokens[i].start);
            // ckb_debug(json + tokens[i].start);
            json[tokens[i].end] = old_char;
            i += 1;
            break;
        }
        case JSMN_ARRAY:
        case JSMN_OBJECT:
        {
            int nested_count;
            char old_char = json[tokens[j].end];
            if (_json_to_table(L, json + tokens[j].start, tokens[j].end - tokens[j].start, &nested_count) != CKB_SUCCESS)
            {
                return ERROR_JSON_TO_TABLE;
            }
            json[tokens[j].end] = old_char;
            // mark table key
            old_char = json[tokens[i].end];
            json[tokens[i].end] = '\0';
            lua_setfield(L, -2, json + tokens[i].start);
            // ckb_debug(json + tokens[i].start);
            json[tokens[i].end] = old_char;
            i += nested_count;
            break;
        }
        default:
            return ERROR_JSON_TO_TABLE;
        }
    }
    return CKB_SUCCESS;
}

int _json_to_table_internal_array(lua_State *L, char *json, jsmntok_t *tokens, int count)
{
    int k = 1;
    for (int i = 1; i < count; ++i, ++k)
    {
        switch (tokens[i].type)
        {
        case JSMN_PRIMITIVE:
        case JSMN_STRING:
        {
            _json_handle_primitive_and_string(L, json, tokens, i);
            lua_rawseti(L, -2, k);
            break;
        }
        case JSMN_OBJECT:
        case JSMN_ARRAY:
        {
            int nested_count;
            if (_json_to_table(L, json + tokens[i].start, tokens[i].end - tokens[i].start, &nested_count) != CKB_SUCCESS)
            {
                return ERROR_JSON_TO_TABLE;
            }
            lua_rawseti(L, -2, k);
            i += nested_count - 1;
            break;
        }
        default:
            return ERROR_JSON_TO_TABLE;
        }
    }
    return CKB_SUCCESS;
}

#endif