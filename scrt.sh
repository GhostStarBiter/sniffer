#!/bin/sh
$PATH=$PATH:.
$SNIF=cat

echo -e "Enter type of net connection: eth wlan?\n or type --help for helpscreen"
read $conn_type
##
case "$conn_type" in
  [-] [-] [hH] [eE] [lL] [pP] ) echo "Screening helpscreen";;
  [eE] [tT] [hH] | [wW] [lL] [aA] [nN] ) read -p "Enter ip adress: " $ip;;
  * ) echo "Entered not correct type of net connection! Type --help for screening help"
      exit 1;;
ecas

case "$ip" in
  [0-9][0-9][0-9].[0-9][0-9][0-9].[0-9] ) echo "$SNIF $conn_type $ip"
  * ) echo "Entered not correct ip adress! " 
      exit 1 ;;
ecas 


exit 0
