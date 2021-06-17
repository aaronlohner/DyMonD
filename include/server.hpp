#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sniffed_info.pb.h>
#include <string>
#include <sniffer.hpp>
using namespace std;

#define PORT 8080
// extern int server_fd, new_socket;
// extern struct sockaddr_in address;
// extern int opt;
// extern int addrlen;

int setup_server();

int add_to_flow_array(flow *flow);

int add_to_flow_array(flow *flow, double RST);

int send_message(vector<struct flow*> flowarray);

int receive_message();