#!/bin/bash
cd protos
# Compile protos for C++ and Python
protoc --cpp_out=../proto_gen --python_out=../proto_gen sniffed_info.proto
cd ..
mv proto_gen/sniffed_info.pb.h include/