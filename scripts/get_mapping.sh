#!/bin/bash
echo -n "$(./scripts/get_interface.sh $1) "
./scripts/get_ip.sh $1
