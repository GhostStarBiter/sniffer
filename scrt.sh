#!/bin/sh
#
#
#
[ -e daemon_calls.txt ] && continue || touch daemon_calls.txt /home/$(whoami)/
#
echo $(date) >> /home/$(whoami)/daemon_calls.txt
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
then echo "start done" 	# command exec. #exec program with parameter $1 (e.i. start)
elif [ "$1" = 'stop' ]
then echo "stop done"	# command exec. #exec program with parameter $1 (e.i. stop)
elif [ "$1" = 'show' ] && [ "$3" = 'count' ]
then echo "$1 $2 $3"	# command exec. #exec program with parameters $1, $2, $3 (e.i. show ___.___.___.___ count)
elif [ "$1" = 'select' ] && [ "$2" = 'iface' ] && [ -n "$3" ]
then echo "$1 $2 $3"	# command exec. #exec program with parameter $1, $2, $3 (e.i. select iface ____)
elif [ "$1" = 'stat' ] && [ -n $2 ]
then echo "Show stat iface $2"	# command exec. #exec program with parameter $1, $2 (e.i. stat ____)
fi
exit 0
