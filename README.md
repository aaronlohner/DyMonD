# DyMonD

DyMonD is a framework that **Dy**namically **Mon**itors an application, **D**iscovers its service components and visualizes them together with some performance metrics in the form of a call graph.

The framework can be run as a standalone module or by communicating with a controller.

## As Standalone
1. Run the bash script `sniffer.sh` with desired options to compile and run the sniffer. Once compiled, future runs can be made on the executable `sniffer` instead, with the ability to use the same options.

The sniffer program will sniff the given interface/file, produces the `logs/log.txt` and `flows/flows.csv` files and ends.

## With Controller
### Interface Mode
The instructions below indicate how to run the application while monitoring the connections for a running YCSB client container. Running the application for a different container would be similar.

1. Open three shell windows on the `compute-04` node.

In the first shell:

2. Grab the network interface of the YCSB webserver to sniff. To do so, run `sudo docker exec -it webserver ip a`
The output should be two interfaces: the loopback interface a second interface written in the format of `<number>: <interface name>@<letters><number>`.
3. Exit the docker container (should be done automatically) and run `ip a|grep ^<number>` using the final `<number>` portion from the output above. The output shows the localhost's interface name connected to the YCSB webserver container in the same format as above.
4. In the `DyMonD` repository, run the bash script `sniffer.sh` *without* any options to compile and run the sniffer.

In the second shell:

5. Enter the following command to open the YCSB container: `sudo docker exec -it ycsbclient bash`
6. Run `cd YCSBCLIENT/bin`, then run the YCSB workload by using the following command (note that once this command is entered, the workload will run for 60 seconds, so the next step (step 7) should be executed immediately after this step):

`./ycsb run jdbc  -P ../workloads/workloadc  -p jdbc.driver=com.mysql.jdbc.Driver  -p db.url=jdbc:mysql://172.16.1.8:3306/YCSB  -p db.user=root  -p db.passwd=root  -s  -threads 20  -target 0  -p measurementtype=timeseries  -p timeseries.granularity=20000`

7. In the third shell, in the `DyMonD` repository, run the client with the interface option by running `python3 script.py -i <interface> [-w <log>]`. Note that omitting the `<interface>` argument will use the default interface `e69b93ccc8384_l`.

The sniffer program will sniff the given interface and sends the results to the client, which subsequently produces the call graph for the application being monitored in the `json` directory (default name of call graph file is `out.json`).

### File Mode
1. Open two shell windows on the `compute-04` node.
2. In the first shell, in the `DyMonD` repository, run the bash script `sniffer.sh` *without* any options to compile and run the sniffer.
3. In the second shell, in the `DyMonD` repository, run the client with the pcap file option by running `python3 script.py -f <filename> [-w <log>]`. Note that omitting the `<filename>` argument will use the default file `teastoreall.pcap` located in the `captures` folder. Note: when running this script in file mode using the default for the first time, the `captures` directory must first be created in the root of the repository and the file must be placed in that directory (it is not part of this repository).

The sniffer program will sniff the given file and sends the results to the client, which subsequently produces the call graph for the application being monitored in the `json` directory (default name of call graph file is `out.json`).

*To clear memcache before running ycsb worload*
telnet 172.17.0.2 11211
flush_all
quit

*To run teastore workload*
sudo docker exec -it generator bash
java -jar httploadgenerator.jar loadgenerator

java -jar httploadgenerator.jar director -s 172.20.0.2 -a ./low2.csv -l ./teastore_browse.lua -t 50
*gateway interface:*
br-39ff5688aa92

*To filter through a docker container*
sudo docker inspect 615fcfe8b0fe | grep "IP" | head -n30