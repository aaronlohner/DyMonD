The agent (sniffer file) is the sniffer reads network traffic form a pre-recorded network traffic (i.e. the pcap file) and produces "log.txt" that contains the captured communications flows.  The controller program reads this "log.txt" file and converts it to call graph through describing nodes and edges in a json file for visualization. The last step is to run the visualization tool (WEBVOWL file) by opening the index.html file and choosing the produced .json file as a source for ontology file to view.

For the first time, you should compile the agent program by running ""g++ -o sniffer sniffer.cpp -lpcap -lboost_filesystem -lboost_system"; the indicated dependencies in the command should be installed. Afterwards, you can run the agent program by running "sudo ./sniffer" in the terminal.

The objective of your task is to convert the agent(i.e. sniffer) and controller programs to client-server one and using a more efficient way to serialize the data between them (i.e the data dumped into log.txt file) such as Google- protobuf used in the prototype.

`cd protos`
`protoc --cpp_out=../proto_gen --python_out=../proto_gen sniffed_info.proto`
`cd ..`
`mv proto_gen/sniffed_info.pb.h include/`
g++ -o sniffer sniffer.cpp server.cpp proto_gen/sniffed_info.pb.cc -I/mnt/c/Users/Aaron/COMP_Research/DyMonD/include -lpcap -lboost_filesystem -lboost_system `pkg-config --cflags --libs protobuf`
OR
g++ -o sniffer sniffer.cpp server.cpp proto_gen/sniffed_info.pb.cc -I/home/alohne/DyMonD/include -lpcap -lboost_filesystem -lboost_system `pkg-config --cflags --libs protobuf`

`./sniffer`
`python client.py`
OR
`python client2.py`

INSTRUCTIONS TO RUN APP LIVE
1- open two ssh shell windows to compute=-04 node
2- At the first shell window:
•	`sudo docker exec -it ycsbclient bash`
•	`cd YCSBCLIENT/bin`
2- At the second shell window: 
•	Grab the network interface of the YCSB webserver to sniff. To do so, run "sudo docker exec -it webserver ip a", it should output two interfaces, the loopback one and other one in the format of <number>:<interface name>@<number>. Please copy the <number> after "@"
•	Exit the docker container (should be done automatically) and at the host run "ip a|grep ^<number>". This will give you the local host's interface name connected to the YCSB webserver container in the format of <number>:<interface name>@<number>, please use the <interface name> shown. I can tell that the host local interface that is connected to the YCSB webserver at "compute-04" node is "e69b93ccc8384_l", However, it's good to know how to grab the host network interface that is connected to any container.
4- `cd /home/shared`:
•	 `g++ -g -o sniffer sniffer.cpp -lpcap -lboost_filesystem -lboost_system`
•	`sudo ./sniffer`
INSTEAD OF STEP 4, compile sniffer in `DyMonD` folder, then copy to `shared` to run
5- The sniffer will ask for the network interface, please input the one you got in step#2 (e69b93ccc8384_l)
6- Go to shell window#1 and run the YCSB workload by using the following command:
`./ycsb run jdbc  -P ../workloads/workloadc  -p jdbc.driver=com.mysql.jdbc.Driver  -p db.url=jdbc:mysql://172.16.1.8:3306/YCSB  -p db.user=root  -p db.passwd=root  -s  -threads 20  -target 0  -p measurementtype=timeseries  -p timeseries.granularity=20000`

NB. you can do steps 5 & 6 in any order.

The sniffer program will sniffer the given interface for 30 seconds and then produces the "log.txt" & "flows.csv" files and ends.
