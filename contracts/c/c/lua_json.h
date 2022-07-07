#ifndef CKB_LUA_JSON
#define CKB_LUA_JSON

#include "header.h"
#include "inject.h"
#include "jsmn.h"

int _json_to_table_internal(lua_State *, char *, jsmntok_t *, int, int);

// int _table_to_json(lua_State *L, int table_pos, uint8_t *cache, size_t size, size_t offset)
// {
//     if (!lua_istable(L, table_pos))
//     {
//         return ERROR_TABLE_TO_SJON;
//     }
//     int ret = CKB_SUCCESS;
//     bool is_array = false;
//     lua_pushnil(L);
//     // check first element
//     if (lua_next(L, table_pos))
//     {
//         // assume array if first key is number
//         cache[offset++] = (is_array = lua_isnumber(L, -2)) ? '[' : '{';
//         cache[offset++] = '\"';
//         const char *key = lua_tostring(L, -2);
//         memcpy(cache + offset, key, strlen(key));
//         offset += strlen(key);
//         cache[offset++] = '\"';
//         cache[offset++] = ':';
//         switch (lua_type(L, -1))
//         {
//             case LUA_TNUMBER:
//             {
//                 const char *value = lua_tostring(L, -1);
//                 memcpy(cache + offset, value, strlen(value));
//                 offset += strlen(value);
//                 break;
//             }
//             case LUA_TTABLE:
//             {
//                 CHECK_RET(_table_to_json(L, lua_gettop(L), cache + offset, size - offset, 0));
//                 break;
//             }
//             default:
//             {
//                 cache[offset++] = '\"';
//                 const char *value = lua_tostring(L, -1);
//                 memcpy(cache + offset, value, strlen(value));
//                 offset += strlen(value);
//                 cache[offset++] = '\"';
//                 break;
//             }
//         }
//         // pop value
//         lua_pop(L, -1);
//         // check remain elements
//         while (lua_next(L, table_pos))
//         {
//             cache[offset++] = ',';
//             cache[offset++] = '\"';
//             const char *key = lua_tostring(L, -2);
//             memcpy(cache + offset, key, strlen(key));
//             offset += strlen(key);
//             cache[offset++] = '\"';
//             cache[offset++] = ':';
//             switch (lua_type(L, -1))
//             {
//                 case LUA_TNUMBER:
//                 {
//                     const char *value = lua_tostring(L, -1);
//                     memcpy(cache + offset, value, strlen(value));
//                     break;
//                 }
//                 case LUA_TTABLE:
//                 {
//                     CHECK_RET(_table_to_json(L, -1, cache + offset, size - offset, 0));
//                     break;
//                 }
//                 default:
//                 {
//                     cache[offset++] = '\"';
//                     const char *value = lua_tostring(L, -1);
//                     memcpy(cache + offset, value, strlen(value));
//                     offset += strlen(key);
//                     cache[offset++] = '\"';
//                     break;
//                 }
//             }
//         }
//     }
//     cache[offset++] = is_array ? ']' : '}';
//     return CKB_SUCCESS;
// }

int _json_to_table(lua_State *L, char *json, size_t len, int *out_count)
{
    // make sure the end of bytes is ZERO
    json[len] = '\0';
    ckb_debug(json);

    jsmn_parser parser;
    jsmntok_t tokens[MAX_JSON_TOKEN_COUNT];

    jsmn_init(&parser);
    int count = jsmn_parse(&parser, json, len, tokens, MAX_JSON_TOKEN_COUNT);
    if (count < 1 || tokens[0].type != JSMN_OBJECT)
    {
        return ERROR_JSON_TO_TABLE;
    }
    if (out_count)
    {
        *out_count = count;
    }
    
    lua_newtable(L);
    return _json_to_table_internal(L, json, tokens, 1, count);
}

int _json_to_table_internal(lua_State *L, char *json, jsmntok_t *tokens, int start, int count)
{
    // iterate key/value pairs, first is key, second is value
    for (int i = start; i < count; ++i)
    {
        int j = i + 1;
        switch (tokens[j].type)
        {
            case JSMN_PRIMITIVE:
            case JSMN_STRING:
            {
                if (strncmp(json + tokens[j].start, "true", strlen("true")) == 0)
                {
                    lua_pushboolean(L, true);
                }
                else if (strncmp(json + tokens[j].start, "false", strlen("false")) == 0)
                {
                    lua_pushboolean(L, false);
                }
                else
                {
                    lua_pushlstring(L, json + tokens[j].start, tokens[j].end - tokens[j].start);
                }
                char old_char = json[tokens[i].end];
                json[tokens[i].end] = '\0';
                lua_setfield(L, -2, json + tokens[i].start);
                // ckb_debug(json + tokens[i].start);
                json[tokens[i].end] = old_char;
                i += 1;
                break;
            }
            case JSMN_ARRAY:
            {
                lua_newtable(L);
                for (int k = 1; k <= tokens[j].size; ++k)
                {
                    if (strncmp(json + tokens[j + k].start, "true", strlen("true")) == 0)
                    {
                        lua_pushboolean(L, true);
                    }
                    else if (strncmp(json + tokens[j + k].start, "false", strlen("false")) == 0)
                    {
                        lua_pushboolean(L, false);
                    }
                    else
                    {
                        lua_pushlstring(L, json + tokens[j + k].start, tokens[j + k].end - tokens[j + k].start);
                    }
                    lua_rawseti(L, -2, k);
                }
                char old_char = json[tokens[i].end];
                json[tokens[i].end] = '\0';
                lua_setfield(L, -2, json + tokens[i].start);
                // ckb_debug(json + tokens[i].start);
                json[tokens[i].end] = old_char;
                i += tokens[j].size + 1;
                break;
            }
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
            {
                return ERROR_JSON_TO_TABLE;
            }
        }
    }
    return CKB_SUCCESS;
}

#endif