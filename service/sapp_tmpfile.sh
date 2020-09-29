#!/bin/sh
install_path=$1
conf_path=$2
echo "d ${install_path}/log          	    0755 - -   30d -" >>${conf_path}/sapp_tmpfile.conf