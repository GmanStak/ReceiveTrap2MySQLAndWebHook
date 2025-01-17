i#!/bin/bash
 ip=$1
 message=$2
 ARR=($message)
 if [[ ${ARR[2]} =~ ^\.1\.3\.6\.1\.4\.1\.37945 ]];then
         level=`exec ./include-snmp/pass.sh ${ARR[2]}`
 else
         level=5
 fi
 echo $level $message