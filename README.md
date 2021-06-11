The agent (sniffer file) is the sniffer reads network traffic form a pre-recorded network traffic (i.e. the pcap file) and produces "log.txt" that contains the captured communications flows.  The controller program reads this "log.txt" file and converts it to call graph through describing nodes and edges in a json file for visualization. The last step is to run the visualization tool (WEBVOWL file) by opening the index.html file and choosing the produced .json file as a source for ontology file to view.

For the first time, you should compile the agent program by running ""g++ -o sniffer sniffer.cpp -lpcap -lboost_filesystem -lboost_system"; the indicated dependencies in the command should be installed. Afterwards, you can run the agent program by running "sudo ./sniffer" in the terminal.

The objective of your task is to convert the agent(i.e. sniffer) and controller programs to client-server one and using a more efficient way to serialize the data between them (i.e the data dumped into log.txt file) such as Google- protobuf used in the prototype.

`cd protos`
`protoc --cpp_out=../proto_gen sniffed_info.proto`
`protoc --python_out=../proto_gen sniffed_info.proto`
`cd ..`
`mv proto_gen/sniffed_info.pb.h include/`
g++ -o sniffer sniffer.cpp server.cpp proto_gen/sniffed_info.pb.cc -I/mnt/c/Users/Aaron/COMP_Research/DymonD/include -lpcap -lboost_filesystem -lboost_system `pkg-config --cflags --libs protobuf`

`./sniffer`
`python client.py`