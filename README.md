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

7. In the third shell, in the `DyMonD` repository, run the client with the interface option by running `python3 script.py -i [INTERFACE]` (run `python3 script.py -h` for help with this script's options).

The sniffer program will sniff the given interface and sends the results to the client, which subsequently produces the call graph for the application being monitored in the `json` directory.

### File Mode
1. Open two shell windows on the `compute-04` node.
2. In the first shell, in the `DyMonD` repository, run the bash script `sniffer.sh` *without* any options to compile and run the sniffer.
3. In the second shell, in the `DyMonD` repository, run the client with the pcap file option by running `python3 script.py -f [FILE]` (run `python3 script.py -h` for help with this script's options). Note: when running this script in file mode using the default for the first time, the `captures` directory must first be created in the root of the repository and the file must be placed in that directory (it is not part of this repository).

The sniffer program will sniff the given file and sends the results to the client, which subsequently produces the call graph for the application being monitored in the `json` directory.

*To clear memcache before running ycsb worload*
telnet 172.17.0.2 11211
flush_all
quit

*To install teastore workload (in my home dir)*
sudo docker-compose -f ./docker-compose_default.yaml up -d

*To run teastore workload*
sudo docker exec -it generator bash
java -jar httploadgenerator.jar loadgenerator

java -jar httploadgenerator.jar director -s 172.20.0.2 -a ./low2.csv -l ./teastore_browse.lua -t 2
**changed from 50 threads to 2**

*gateway interface:*
br-39ff5688aa92

*To filter through a docker container*
sudo docker inspect 615fcfe8b0fe | grep "IP" | head -n30

*To start up sockshop containers*
sudo docker start docker-compose_queue-master_1 docker-compose_orders_1 docker-compose_payment_1 docker-compose_orders-db_1 docker-compose_catalogue-db_1 docker-compose_carts-db_1 docker-compose_front-end_1 docker-compose_carts_1 docker-compose_user-db_1 docker-compose_user_1 docker-compose_catalogue_1 docker-compose_edge-router_1 docker-compose_shipping_1 docker-compose_rabbitmq_1

*To run sockshop workload*
sudo docker run --net=host weaveworksdemos/load-test -h localhost -r 10000 -c 2 -d 1

sudo docker run -it --entrypoint /bin/bash weaveworksdemos/load-test
entrypoint:/usr/local/bin/runLocust.sh

node: 10.0.1.22
compute: 10.0.1.54

*printing the length somehow changes it...*

describe system architecture in doc, using images+desc

if non-gateway service is provided but hop extractor eventually falls on gateway, all flows that do not contain gateway as server will be omitted