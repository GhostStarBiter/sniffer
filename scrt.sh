#!/bin/sh
$PATH=$PATH.
$SNIF=program

echo -e "Enter type of net connection: eth or wlan?\n"
read $conn_type
##
case "$conn_type" in
  eth | wlan ) read -p "Enter ip adress: " $ip;;
  * ) echo "Entered not correct type of net connection!"
      exit 1;;
ecas

if [ -n $ip | "$conn_type"="eth" | "$conn_type"="wlan" ]
then $SNIF $conn_type $ip
elif exit 1
fi

exit 0
