#!/bin/sh
$PATH=$PATH.

echo -e "Enter type of net connection: eth or wlan?\n"
read $conn_type
##
if [ $conn_type = eth ]
then echo -e "Enter ip address: \n"
read $ip
fi
if [ -n $ip ]
then program $conn_type $ip
fi
##
if [ $conn_type = wlan ]
then echo -e "Enter ip address: \n"
read $ip
fi
if [ -n $ip ]
then program $conn_type $ip
fi
