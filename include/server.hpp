#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
//#include <sniffed_info.pb.h>
#include <string>
#include <agent.hpp> // needed for flow struct defn
using namespace std;

#define PORT 9080

void setup_server();

void stop_server();

//void add_to_flow_array(flow *flow); // uses protobuf

void add_to_flow_array(flow *flow, double RST, double time);

bool is_server(flow *flow);

void get_service_type(flow *flow, char *service);

void send_message(vector<struct flow*> flowarray);

//void send_message(FlowArray flowarray); // uses protobuf

void send_message(string flowarray);

void send_message_test(string str);

void send_message();

void receive_message(char *inputBuffer, bool suppress_output);