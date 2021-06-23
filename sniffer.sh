#!/bin/bash
cd protos
# Compile protos for C++ and Python
protoc --cpp_out=../proto_gen --python_out=../proto_gen sniffed_info.proto
cd ..
mv proto_gen/sniffed_info.pb.h include/
g++ -o sniffer sniffer.cpp server.cpp proto_gen/sniffed_info.pb.cc -Iinclude -lpcap -lboost_filesystem -lboost_system `pkg-config --cflags --libs protobuf`
# Start up sniffer
./sniffer
