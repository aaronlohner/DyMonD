The agent (sniffer file) is the sniffer reads network traffic form a pre-recorded network traffic (i.e. the pcap file) and produces "log.txt" that contains the captured communications flows.  The controller program reads this "log.txt" file and converts it to call graph through describing nodes and edges in a json file for visualization. The last step is to run the visualization tool (WEBVOWL file) by opening the index.html file and choosing the produced .json file as a source for ontology file to view.

**Run in live mode**
1. Open three ssh shell windows to compute-04 node
2. In the first shell, execute the following commands:
    - `sudo docker exec -it ycsbclient bash`
    - `cd YCSBCLIENT/bin`
*Steps 2-7* are all done in the second shell
3. In the second shell, grab the network interface of the YCSB webserver to sniff. To do so, run:
`sudo docker exec -it webserver ip a`
The output should be two interfaces: the loopback interface a second interface written in the format of <number>: <interface name>@<letters><number>.
4. Exit the docker container (should be done automatically) and run
`ip a|grep ^<number>` using the final <number> portion from the output above.
The output shows the localhost's interface name connected to the YCSB webserver container in the same format as above.
5. Run
`cd /home/alohne/DyMonD`
then compile the server code by running
`cat sniffer.sh`
and then by running all the lines of code in this script except the first and last ones.
6. Copy the compiled sniffer code into the shared folder by running
`cp ../../shared sniffer`
Then run
`cd ../../shared`
7. Start the server with
`sudo ./sniffer`
8. In the third shell, run
`cd /home/alohne/DyMonD`
then start the client by running
`python client2.py`
9. In the first shell, run the YCSB workload by using the following command:
`./ycsb run jdbc  -P ../workloads/workloadc  -p jdbc.driver=com.mysql.jdbc.Driver  -p db.url=jdbc:mysql://172.16.1.8:3306/YCSB  -p db.user=root  -p db.passwd=root  -s  -threads 20  -target 0  -p measurementtype=timeseries  -p timeseries.granularity=20000`
10. In the third shell, enter the information prompted by the client to start sniffing the workload

The sniffer program will sniff the given interface for 30 seconds and then produces the "log.txt" & "flows.csv" files and ends.
