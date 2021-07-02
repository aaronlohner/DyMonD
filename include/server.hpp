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

void setup_server();

void stop_server();

void add_to_flow_array(flow *flow);

void add_to_flow_array(flow *flow, double RST);

void send_message(vector<struct flow*> flowarray);

void receive_message(char *inputBuffer);