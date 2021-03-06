#!/bin/bash
cd protos
# Compile protos for Python controller script
protoc --python_out=../proto_gen sniffed_info.proto
cd ..
g++ -o agent src/agent.cpp src/server.cpp -Iinclude -lpcap -lboost_filesystem -lboost_system -pthread -lpython3.7m
mkdir -p captures flows json logs
