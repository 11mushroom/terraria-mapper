# Usage
  has a chanse of crashing server
  ```bash
  nmap --script terraria-mapper.nse -p <ports> <hosts>
  ```
  with bruteforce of version:
  ```bash
  nmap --script terraria-mapper.nse --script-args 'bf_v' -p <ports> <hosts>
  ```
  ```bash
  # custom range [from, to], bf_v={from, to}
  nmap --script terraria-mapper.nse --script-args 'bf_v={400,200}' -p <ports> <hosts>
  ```
  bruteforcing version is very noticable from console


  with version picking:
  ```bash
  nmap --script terraria-mapper.nse --script-args 'pick_v' -p <ports> <hosts>
  ```
  ```bash
  # use custom version table from a given path
  nmap --script terraria-mapper.nse --script-args 'pick_v=vtable.lua' -p <ports> <hosts>
  ```
  version picking is a little bit less noticable 
  than bruteforce and can be faster

# Possible side effects of bruteforcing version
  server crash, temporary increase in storage IO
  and CPU load, dos, messed up player cap, loss of friends

# Possible side effects of version picking
  server crash, a little temporary increase in storage IO
  and CPU load, dos, messed up player cap, friends' suspicion

