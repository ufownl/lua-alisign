#include "alisign.hpp"
#include "sign.hpp"

namespace {

int alisign_sign(lua_State* L) {
  size_t data_len;
  auto data = reinterpret_cast<const uint8_t*>(lua_tolstring(L, 1, &data_len));
  auto sign_type = lua_tostring(L, 2);
  auto private_key = lua_tostring(L, 3);
  auto result = alisign::sign(data, data_len, sign_type, private_key);
  if (result.empty()) {
    lua_pushnil(L);
  } else {
    lua_pushlstring(L, reinterpret_cast<const char*>(result.data()),
                    result.size());
  }
  return 1;
}

int alisign_verify(lua_State* L) {
  size_t data_len;
  auto data = reinterpret_cast<const uint8_t*>(lua_tolstring(L, 1, &data_len));
  size_t sign_len;
  auto sign = reinterpret_cast<const uint8_t*>(lua_tolstring(L, 2, &sign_len));
  auto sign_type = lua_tostring(L, 3);
  auto public_key = lua_tostring(L, 4);
  auto result = alisign::verify_sign(data, data_len, sign, sign_len, sign_type,
                                     public_key);
  lua_pushboolean(L, result);
  return 1;
}

}

int luaopen_alisign(lua_State* L) {
  constexpr const luaL_Reg reg[] = {
    {"sign", alisign_sign},
    {"verify", alisign_verify},
    {nullptr, nullptr}
  };
  luaL_register(L, "alisign", reg);
  return 1;
}
