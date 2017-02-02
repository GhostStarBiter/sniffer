#!/bin/sh
$PATH=$PATH.
$SNIF=program

echo -e "Enter type of net connection: eth or wlan?\n"
read $conn_type
##
if [ "$conn_type" = "eth" ]
then echo -e "Enter ip address: \n"
read $ip
elif [ "$conn_type" = "wlan" ]
then echo -e "Enter ip address: \n"
read $ip
elif [ -z "$conn_type" ]
then 
echo "Connection type not entered. Quit."
exit 1
fi

if [ -n $ip ]
then $SNIF $conn_type $ip
fi

exit 0
