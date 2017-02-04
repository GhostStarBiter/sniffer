#!/bin/sh
#
#
if [ "$1" = 'start' ]
then echo "start done"
elif [ "$1" = 'stop' ]
then echo "stop done"
elif [ "$1" = 'show' ] && [ "$3" = 'count' ]
then echo "$1 $2 $3"
elif [ "$1" = 'select' ] && [ "$2" = 'iface' ] && [ -n "$3" ]
then echo "$1 $2 $3"
elif [ "$1" = 'stat' ] && [ -n $2 ]
then echo "Show stat iface $2"
elif [ "$1" = '--help' ]; then 
### help section ###
echo "Commands:"
echo "\n"
echo "\t start\t packets are being sniffed from now on from default iface(eth0);"
echo "\n"
echo "\t stop\t packets are not sniffed;"
echo "\n"
echo "\t show [ip] count\t print number of packets received from ip address;"
echo "\n"
echo "\t select iface [iface]\t select interface for sniffing eth0, wlan0, ethN, wlanN...;"
echo "\n"
echo "\tstat [iface]\t show all collected statistics for particular interface, if [iface] omitted - for all interfaces;"
fi

exit 0
