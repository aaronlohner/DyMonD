#!/bin/bash
cd protos
# Compile protos for Python controller script
protoc --python_out=../proto_gen sniffed_info.proto
cd ..
g++ -o agent src/agent_no_model.cpp src/server.cpp -Iinclude -lpcap -lboost_filesystem -lboost_system -pthread
mkdir -p captures flows json logs
# Start up agent
# case $1 in
# 	-t|-i|-f) sudo ./agent $1 $2;;
# 	-p) sudo ./agent $1;;
# 	*) sudo ./agent;;
# esac
