#!/bin/bash
sudo docker exec -it $1 ip a | grep -o '[[:digit:]]\{3\}\.[[:digit:]]\{2\}\.[[:digit:]]\{1\}\.[[:digit:]]\{1,2\}' | xargs
