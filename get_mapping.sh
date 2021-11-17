#!/bin/bash
echo -n "$(./get_interface.sh $1) "
./get_ip.sh $1
