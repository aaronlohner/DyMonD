# DyMonD
DyMonD is a framework that **Dy**namically **Mon**itors an application, **D**iscovers its service components and visualizes them together with some performance metrics in the form of a call graph. It consists of three main components: a sniffer, a controller and a web interface (the web interface is not part of this repository). For more details on this framework such as how to run it and an overview of its architecture, please see the [wiki page](https://github.com/a-a-lohn/DyMonD/wiki).

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
sudo docker run --net=host weaveworksdemos/load-test -h localhost -r 10000 -c 2

sudo docker run -it --entrypoint /bin/bash weaveworksdemos/load-test
entrypoint:/usr/local/bin/runLocust.sh

node: 10.0.1.22
compute: 10.0.1.54

*printing the length somehow changes it...*

describe system architecture in doc, using images+desc

if non-gateway service is provided but hop extractor eventually falls on gateway, all flows that do not contain gateway as server will be omitted

tcp logging can contain repeated flows since it's not what's actually being used, it's just spitting out the captured flows

sudo tcpdump -i <interface> -w <filename.pcap>