#!/bin/sh
#
#	Before executing the script need to be done symbolic link to /usr/local/bin
#	Before executing program need to be done symbolic link to /usr/local/bin
#
[ -d /home/$(whoami)/snifer ] && continue || mkdir /home/$(whoami)/snifer
[ -e daelog.txt ] && continue || touch daelog.txt /home/$(whoami)/snifer
#
echo { $(date) $1 $2 $3 } >> /home/$(whoami)/daelog.txt
echo "\nInterfaces avaliable: \n" >> /home/$(whoami)/daelog.txt
ls /sys/class/net >> /home/$(whoami)/daelog.txt

if [ -z "$1" ] || [ "$1" = '--help' ]
then	echo "Commands to use:"
	echo "\n"
	echo "\t start\t packets are being sniffed from now on from default iface(eth0);"
	echo "\n"
	echo "\t stop\t packets are not sniffed;"
	echo "\n"
	echo "\t show [ip] count\t print number of packets received from ip address;"
	echo "\n"
	echo "\t select iface [iface]\t select interface for sniffing eth0, wlan0, ethN, wlanN...;"
	echo "\n"
	echo "\tstat [iface]\t show all collected statistics for particular interface, if [iface] omitted - for all interfaces;\n" 
elif [ "$1" = 'start' ]
then echo "start done" 	# snfrdaemon $1
elif [ "$1" = 'stop' ]
then echo "stop done"	# snfrdaemon $1
elif [ "$1" = 'show' ] && [ "$3" = 'count' ]
then echo "$1 $2 $3"	# snfrdaemon $1 $2 $3
elif [ "$1" = 'select' ] && [ "$2" = 'iface' ] && [ -n "$3" ]
then echo "$1 $2 $3"	# snfrdaemon $1 $2 $3
elif [ "$1" = 'stat' ] && [ -n $2 ]
then echo "Show stat iface $2"	# snfrdaemon $1 $2
fi
exit 0
