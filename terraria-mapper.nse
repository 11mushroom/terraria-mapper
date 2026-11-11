-- SPDX-License-Identifier: MPL-2.0
-- Copyright (c) 2026 11mushroom
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

local nmap = require("nmap")
local stdnse = require("stdnse")
local match = require("match")

description =[[

this script detects terraria servers

terraria servers have a chanse to crash
during scans/checks
can mess with target's player cap.

can bruteforce protocol version if argument "bf_v" is passed.
side effects of bruteforcing:
  - temporary increase in storage IO and CPU loads
    on target server.
  - very noticable from target's console.
  - sometimes can disrupt work of a target server
    and in some cases even crash it.

]]

---
-- @usage
-- nmap --script terraria-mapper.nse -p 1-8000 <host>
---
-- @output
-- 80/tcp   open  http
-- 443/tcp  open  ssl
-- 5089/tcp open  unknown
-- 6076/tcp open  terraria
-- 7777/tcp open  terraria
--
---
-- @args
-- bf_v
--   enables bruteforce of terraria protocol version
--   can temporarily increase storage IO and CPU loads
--   on target server and has a small chance of
--   crashing it or disrupting a player cap.
--
--   also very noticable from target's console.
--
-- bf_range={from, to}
--   [from, to] inclusive range of protocol versions to try
--   if it's not set, the default [400, 200] range is used

author = "11mushroom"
license = "MPL-2.0--See https://mozilla.org/MPL/2.0/"
categories = {"version", "intrusive", "dos"}

-- huge thanks to the authors of terraria_protocol Rust crate:
--   https://crates.io/crates/terraria-protocol
--   https://codeberg.org/Lonami/terry/src/branch/master/terraria-protocol
--   https://github.com/Lonami/terry/blob/master/terraria-protocol
-- 
-- and to the authors of this page:
--   https://seancode.com/terrafirma/net.html
-- 

-----------parsing functions-------------

local packs

packs = {
  {
    ID = 0x01, -- connect (client)
    deserializer=function(self, payload)
      return {ID=nil}
    end,
    serializer=function(self, packdata)
      local mlen = #packdata.message & 0xff
      return string.char(self.ID, mlen)..packdata.message:sub(1, mlen)
    end
  },
  {
    ID = 0x02, -- disconnect (server)
    deserializer=function(self, payload)
      local len = #payload
      local reason = {type = nil, message = nil}
      
      reason.type = payload:byte(2)

      local rlen = payload:byte(3)

      if rlen~=nil and rlen+4 <= len then
        reason.message = payload:sub(4, 4+rlen)
      end
      
      return {ID = self.ID, reason = reason}

    end,
    serializer=function(self, packdata)
      return nil
    end,
  },
  {
    ID = 0x03, -- assign slot (server)
    deserializer=function(self, payload)
      local result = {ID=nil, slot=nil}
      if #payload==3 then
        result.ID=self.ID
        result.slot=string.unpack('<I2', payload:sub(2,3))
      end

      return result
    end,
    serializer=function(self, packdata)
      return nil
    end
  },
  {
    ID = 0x26, -- send password (client)
    deserializer=function(self, payload)
      return {ID = nil}
    end,
    serializer=function(self, packdata)
      if packdata.passwd==nil then
        return nil
      end

      local plen = #packdata.passwd&0xff
      return string.char(self.ID, plen)..packdata.passwd:sub(1, plen)
    end,
  },
  deserialize = function(self, ID, payload)
    for _, pack in ipairs(self) do
      if pack.ID == ID then
        return pack:deserializer(payload)
      end
    end
    return nil      
  end,
  serialize = function(self, ID, packdata)
    for _, pack in ipairs(self) do
      if pack.ID == ID then
        return pack:serializer(packdata)
      end
    end
    return nil
  end,
}

-- load payload into terraria packet
local to_pack = function(data)
  local len = #data + 2
  local resp = string.pack("<I2", len) .. data
  return resp
end

-- read terraria packets
local read_pack = function(socket, try)
  local buf = try(socket:receive_buf(match.numbytes(2), true))
  local len = 0
  -- nmap.log_write("stdout", #buf)
  -- nmap.log_write("stdout", buf:gsub("[^ -~]", function(c) return ("\\x%02x"):format(c:byte()) end))
  if buf ~= nil and #buf==2 then
    len = string.unpack("<I2", buf)
  end
  -- nmap.log_write("stdout", len)
  buf = ""
  if len >= 3 then
    buf = try(socket:receive_buf(match.numbytes(len-2), true))
  end

  return {len = len, ID = buf:byte(1), payload = buf}
end



-----------magic numbers-----------------

local DISCONN = 0x02 -- disconnect
local CONNECT = 0x01 -- connect
local ASNSLOT = 0x03 -- assign slot
local LDNETMD = 0x52 -- load net module
local SNDPSWD = 0x26 -- send password
local REQPSWD = 0x25 -- request password

---------------nmapping------------------

prerule = function()
  -- nmap.log_write("stdout", "terraria mapper")
end

-- try only on open tcp ports
portrule = function(host, port)
  return port.state=="open" and port.protocol=="tcp"
end

action = function(host, port)
  local sock = nmap.new_socket()
  local terraria = false

  -- bruteforce version or not
  local bf_version = stdnse.get_script_args('bf_v') and true or false
  -- bruteforce range
  local from, to = 400, 200
  local v_range = stdnse.get_script_args('bf_range')
  if type(v_range)=='table' and #v_range==2 and
     tonumber(v_range[1])~=nil and tonumber(v_range[2])~=nil then

     from, to = math.abs(math.floor(tonumber(v_range[1]))),
                math.abs(math.floor(tonumber(v_range[2])))
  end


  local catch = function()
    sock:close()
  end
  local try = nmap.new_try(catch)

  local pack
  local v

  try(sock:connect(host.ip, port.number))

  try(sock:send(
    to_pack(packs:serialize(CONNECT, {message = "Terraria"..100}))
  ))

  pack = read_pack(sock, try)

  local parsed_pack = packs:deserialize(pack.ID, pack.payload)

  -- if it looks like a duck, and quacks like a duck,
  if (parsed_pack.ID==ASNSLOT) or
    (pack.ID==LDNETMD) or
    (pack.ID==REQPSWD and #pack.payload==1) or
    (parsed_pack~=nil and parsed_pack.ID==DISCONN and
    parsed_pack.reason.message~=nil)
    then -- it probably is a duck

    terraria=true
    port.version.name = "terraria"..(pack.ID==REQPSWD and "_password" or "")
    nmap.set_port_version(host, port)
  end

  stdnse.sleep(0.3)
  try(sock:close())
  
  -- bruteforce terraria version
  if terraria and bf_version then
    for vers = from, to, (from<=to and 1 or -1) do
      v=vers

      sock = nmap.new_socket()

      try(sock:connect(host.ip, port.number))

      try(sock:send(
        to_pack(packs:serialize(CONNECT,{message = "Terraria"..vers}))
      ))

      -- in case server spams with 0x52 packets first
      for i = 1, 11 do
        pack = read_pack(sock, try)
        if pack.ID~=LDNETMD then
          stdnse.debug(1, "pack.ID: 0x%02x,vers: %03d", pack.ID, vers)
          break
        end
      end

      stdnse.sleep(0.1)

      try(sock:close())

      if pack.ID == ASNSLOT or pack.ID==REQPSWD then
        port.version.version = vers

        -- if requires password
        if pack.ID == REQPSWD then
          port.version.name = port.version.name.."_password"
        end

        nmap.set_port_version(host, port)
        return {version=vers}

      -- in case packet 0x52 still goes through
      elseif pack.ID==LDNETMD then
        nmap.log_write("stdout", "Packet 0x52 disrupted probe!!!")
        return {version=0}
      end

    end
  end
end
