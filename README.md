# sniffer
net traffic sniffer daemon with command line interface
Description:
  1. Daemon saves ip addresses of incoming packets and number of packets from each ip.
  2. Creates log file for time complexity for ip search.
  3. Collected statistics are persistent through reboot.
  4. Command line interface is separate process which interacts with daemon.
      Commands:
      start
      stop
      show [ip] count
      select [iface] (iface - eth0, wLan0, eth[N], wLan[N])
      stat [iface]
      --help
