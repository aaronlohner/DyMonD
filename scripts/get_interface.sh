#!/bin/bash
sudo docker exec -it $1 ip a | grep -o '@[[:alpha:]]\+[[:digit:]]\+:' | grep -o '[[:digit:]]\+:' > grep.txt
ip a |grep -f grep.txt | grep -o ': [[:alnum:]]\+@' | grep -o '[[:alnum:]]\+'
rm grep.txt
