# lua-alisign

Lua module for alipay signature based LuaJIT

## Usage

With OpenResty:

```lua
local alisign = require("alisign")

function sign(params)
  if not params.sign_type then
    return nil
  end
  local t = {}
  for k, v in pairs(params) do
    if k ~= "sign" then
      table.insert(t, k.."="..v)
    end
  end
  table.sort(t)
  local str = ""
  for i, v in ipairs(t) do
    if i > 1 then
      str = str.."&"
    end
    str = str..v
  end
  return ngx.encode_base64(alisign.sign(str, params.sign_type, alipay_app_private_key))
end

function verify_sign(params)
  if not params.sign or not params.sign_type then
    return false
  end
  local t = {}
  for k, v in pairs(params) do
    if k ~= "sign" and k ~= "sign_type" and tostring(v) ~= "" then
      table.insert(t, k.."="..v)
    end
  end
  table.sort(t)
  local str = ""
  for i, v in ipairs(t) do
    if i > 1 then
      str = str.."&"
    end
    str = str..v
  end
  return alisign.verify(str, ngx.decode_base64(params.sign), params.sign_type, alipay_public_key)
end
```
