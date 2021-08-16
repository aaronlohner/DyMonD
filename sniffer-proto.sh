#!/bin/bash
cd protos
# Compile protos for C++ and Python
protoc --cpp_out=../proto_gen --python_out=../proto_gen sniffed_info.proto
cd ..
mv proto_gen/sniffed_info.pb.h include/
g++ -o sniffer src/sniffer.cpp src/server.cpp proto_gen/sniffed_info.pb.cc -Iinclude -lpcap -lboost_filesystem -lboost_system -pthread `pkg-config --cflags --libs protobuf` -lpython3.7m
mkdir -p captures flows json logs
# Start up sniffer
case $1 in
	-t|-i|-f) sudo ./sniffer $1 $2;;
	-p) sudo ./sniffer $1;;
	*) sudo ./sniffer;;
esac