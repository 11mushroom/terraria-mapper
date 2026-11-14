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

can try picking the version using table of known versions
if argument "pick_v" is passed.
  - less aggressive than brutefoce
  - can be faster than brute force
  - can be a little bit less noticable than brutefoce
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
-- bf_v={from, to}
--   [from, to] inclusive range of protocol versions to try
--   if it's not set, the default [400, 200] range is used
--
-- pick_v
--   uses table of known versions to try to pick the version
--   can be faster and a little bit less noticable,
--   and can be less aggressive than bruteforce
--
-- pick_v=path/to/file
--   loads custom table of known versions for picking
--   from a given path to file

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

-----------------------------------------

local vtable = { -- table of known versions
  {326, "1458"},
  {325, "1457"},
  {319, "1456"},
  {318, "1455"},
  {317, "1454"},
  {316, "1453"},
  {315, "1450 1451 1452"},
  {279, "1449"},
  {278, "14481"},
  {277, "1448"},
  {276, "1447"},
  {275, "1446"},
  {274, "1445"},
  {273, "1444"},
  {272, "1443"},
  {271, "1442"},
  {270, "1441"}, -- it's a guess, need a proof for 1441
  {269, "144"},
  {248, "1436"},
  {247, "1435"},
  {246, "1434"},
  {245, "1433"},
  {244, "1432"},
  {243, "1431"},
  {242, "143"},
  {238, "1423"},
}

local find_release=function(where,version)
  for _,p in ipairs(where) do
    if p[1]==version then
      return p[2]
    end
  end
  return nil
end

-----------parsing functions-------------

local packs
packs = {
  [0x01] = {
    ID = 0x01, -- connect (client)
    deserializer=function(self, payload)
      return {ID=nil}
    end,
    serializer=function(self, packdata)
      local mlen = #packdata.message & 0xff
      return string.char(self.ID, mlen)..packdata.message:sub(1, mlen)
    end
  },
  [0x02] = {
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
  [0x03] = {
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
  [0x26] = {
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
    if type(self[ID]) == 'table' then
      return self[ID]:deserializer(payload)
    end
    return {ID=nil}
  end,
  serialize = function(self, ID, packdata)
    if type(self[ID]) == 'table' then
      return self[ID]:serializer(packdata)
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
  if #buf==2 then
    len = string.unpack("<I2", buf)
  end

  -- nmap.log_write("stdout", len)
  buf = ""
  if len >= 3 then
    buf = try(socket:receive_buf(match.numbytes(len-2), true))
  end

  return {len = len, ID = buf:byte(1), payload = buf}
end

local try_read_first = function(socket, try)
  local limits = {
    [0x02] = {5, 260},    -- disconnect 
    [0x03] = {5, 5},      -- assign slot
    [0x25] = {3, 3},      -- request password
    [0x52] = {4, 0xffff}, -- load net module
  }

  local buf = try(socket:receive_buf(match.numbytes(2), true))
  local raw_pack={len = nil, ID = nil, payload = nil}
  if #buf~=2 then
    return nil end

  raw_pack.len = string.unpack("<I2", buf)
  if raw_pack.len < 3 then
    return nil end

  buf = buf..try(socket:receive_buf(match.numbytes(1), true))
  raw_pack.ID = buf:byte(3)

  if limits[raw_pack.ID]==nil or
    raw_pack.len<limits[raw_pack.ID][1] or
    raw_pack.len>limits[raw_pack.ID][2]
    then

    return nil
  end

  buf = buf..try(socket:receive_buf(match.numbytes(raw_pack.len-3), true))
  raw_pack.payload = buf:sub(3,-1)

  return raw_pack
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
  local bf_version = stdnse.get_script_args('bf_v') or false
  -- bruteforce range
  local from, to = 400, 200
  if type(bf_version)=='table' and
     tonumber(bf_version[1])~=nil and tonumber(bf_version[2])~=nil then

     from, to = math.abs(math.floor(tonumber(bf_version[1]))),
                math.abs(math.floor(tonumber(bf_version[2])))
  end
  bf_version = bf_version and true

  local pick_v = stdnse.get_script_args('pick_v') or false
  if type(pick_v) == 'string' then
    vtable=dofile(pick_v)
  end
  pick_v = pick_v and true

  local catch = function()
    stdnse.debug(1, "connection error")
    sock:close()
  end
  local try = nmap.new_try(catch)

  local pack
  local v

  sock:set_timeout(10000)
  try(sock:connect(host.ip, port.number))

  try(sock:send(
    to_pack(packs:serialize(CONNECT, {message = "Terraria"..100}))
  ))

  -- don't waste time on a wrong data
  pack = try_read_first(sock, try)
  
  if pack==nil then
    stdnse.debug(2, "invalid first packed")
    try(sock:close())
    return
  end

  local parsed_pack = packs:deserialize(pack.ID, pack.payload)

  -- if it looks like a duck, and quacks like a duck,
  if (pack.ID~=DISCONN) or
    (parsed_pack.ID==DISCONN and
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

      -- stdnse.sleep(0.1)

      try(sock:close())

      if pack.ID == ASNSLOT or pack.ID==REQPSWD then
        port.version.version = vers

        -- if requires password
        if pack.ID == REQPSWD then
          port.version.name = port.version.name.."_password"
        end

        nmap.set_port_version(host, port)
        return {version=vers, release=find_release(vtable, vers) or 'unknown'}

      -- in case packet 0x52 still goes through
      elseif pack.ID==LDNETMD then
        nmap.log_write("stdout", "Packet 0x52 disrupted probe!!!")
        return {version=0, release='unknown'}
      end

    end
  elseif pick_v then
    for _,vp in ipairs(vtable) do
      local vers, release = vp[1], vp[2]
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

      -- stdnse.sleep(0.1)

      try(sock:close())

      if pack.ID == ASNSLOT or pack.ID==REQPSWD then
        port.version.version = vers

        -- if requires password
        if pack.ID == REQPSWD then
          port.version.name = port.version.name.."_password"
        end

        nmap.set_port_version(host, port)
        return {version=vers, release=release}

      -- in case packet 0x52 still goes through
      elseif pack.ID==LDNETMD then
        nmap.log_write("stdout", "Packet 0x52 disrupted probe!!!")
        return {version=0, release='unknown'}
      end

    end
  end
end
