# Usage
  has a chanse of crashing server
  ```bash
  nmap --script terraria-mapper.nse -p <ports> <hosts>
  ```
  with bruteforce of version:
  ```bash
  nmap --script terraria-mapper.nse --script-args 'bf_v,bf_range={400,300}' -p <ports> <hosts>
  ```
  bruteforcing version is very noticable from console

# Side effects of bruteforcing version
  server crash, temporary increase in storage IO
  and CPU load, dos, messed up player cap, loss of friends
