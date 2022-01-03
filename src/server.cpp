#include <server.hpp>

int server_fd, client_fd, valread;
struct sockaddr_in address;
int opt = 1;
int addrlen = sizeof(address);
char buffer[1024] = {0};
char service[32] = {0};
char empty_buf[0];
string flow_string = "";
string flow_string_smaller = "";
string flow_last = "";

/*
 * Set up server socket and wait for client to connect
 */
void setup_server() {
	//GOOGLE_PROTOBUF_VERIFY_VERSION;

	// Creating socket file descriptor
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		perror("socket failed");
		exit(EXIT_FAILURE);
	}
	
	// Forcefully attaching socket to the port 9080
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
	{
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;// we bind the server to the localhost,
	// and we use INADDR_ANY to allow any client IP address
	address.sin_port = htons(PORT); // defined as 9080
	
	// Forcefully attaching socket to the port 9080
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	if (listen(server_fd, 3) < 0)
	{
		perror("listen");
		exit(EXIT_FAILURE);
	}

	printf("Waiting for controller to connect...\n");
	if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0)
	{
		perror("accept");
		exit(EXIT_FAILURE);
	}
	printf("Connected\n");
}

/*
 * Close the socket conection
 */
void stop_server(){
	close(client_fd);
	printf("Disconnected from controller\n");
}

/*
 * Read incoming message into input buffer
 */
void receive_message(char inputBuffer[], bool suppress_output) {
	if(!suppress_output) printf("Waiting for message from controller...\n");
	int mesg_len_buf, mesg_length;
	// Expect to receive message length first in a 4-byte block immediate followed by the message
	// Only continue once message is received
	while (!valread) valread = recv(client_fd, &mesg_len_buf, 4, 0);
	mesg_length = ntohl(mesg_len_buf);
	recv(client_fd, buffer, mesg_length, 0);
	strncpy(inputBuffer, buffer, mesg_length);
	// Reset global variable for future incoming messages
	memset(buffer, 0, sizeof(buffer));
	valread = 0;
}

/*
 * Add flow element to flow array with RST
 */
void add_to_flow_array(flow *flow, double RST, double time) {
	size_t length = flow_string.size();
	if(length > 1380){
		send_message(flow_string_smaller);
	}
	flow_string_smaller.clear();
	flow_string_smaller = flow_string;
	flow_last.clear();
	flow_last.append(flow->saddr).append(" ");
	flow_last.append(flow->sport).append(" ");
	flow_last.append(flow->daddr).append(" ");
	flow_last.append(flow->dport).append(" ");
	flow_last.append(to_string(flow->NumBytes/time)).append(" ");
	flow_last.append(to_string(is_server(flow))).append(" ");
	get_service_type(flow, service);
	flow_last.append(service).append(" ");
	flow_last.append(to_string(RST)).append("\n");
	flow_string.append(flow_last);
}

/*
 * Add flow element to flow array. Uses protobuf
 */
/*void add_to_flow_array(flow *flow) {
	string data;
	flow_array.SerializeToString(&data);
	size_t length = data.size();
	if(length > 1380){
		send_message(flow_array_smaller);
	} else {
		flow_array_smaller = FlowArray(flow_array);
	}
	Flow *flow_proto = flow_array.add_flows();
	// Populate fields of protobuf Flow with fields from the inputted flow struct fields
	flow_proto->set_s_addr(flow->saddr);
	flow_proto->set_s_port(flow->sport);
	flow_proto->set_d_addr(flow->daddr);
	flow_proto->set_d_port(flow->dport);
	flow_proto->set_num_bytes(flow->NumBytes/30);
	flow_proto->set_is_server(is_server(flow));
	get_service_type(flow, service);
	flow_proto->set_service_type(service);
}*/

/*
 * Determine if the first component in the flow is a server or not
 */
bool is_server(flow *flow){
	char *proto = flow->proto;
	int i = 0;
	while(proto[i] != '\0'){
		i++;
	}
	if(proto[i-1] == 'S') return true;
	return false;
}

/*
 * Populate the service parameter with the name of the service type in the flow
 */
void get_service_type(flow *flow, char *service){
	if(strstr(flow->proto, "Unknown") != NULL) {
		strcpy(service, flow->proto);
	} else {
		int i = 0;
		while(flow->proto[i] != '-'){
			service[i] = flow->proto[i];
			i++;
		}
		service[i] = '\0';
	}
}

/*
 * Send string of flows. Input is not used in method but instead used
 * to differentiate this method from send_message() which takes no input
 */
void send_message(vector<struct flow*> flowarray){
	size_t length = flow_string.size();
	uint32_t nlength = htonl(length);
	// First send message length
	send(client_fd, &nlength, 4, 0);
	send(client_fd, flow_string.c_str(), length, 0);
	// Prepare global variable for future use
	flow_string.clear();
	flow_string.append(flow_last);
}

/*
 * Send array of flows. Uses protobuf
 */
/*void send_message(FlowArray flowarray){
	string data;
	flowarray.SerializeToString(&data);
	size_t length = data.size();
	uint32_t nlength = htonl(length);
	// First send message length
	send(client_fd, &nlength, 4, 0);
	send(client_fd, data.c_str(), length, 0);
	// Reset global variable for future use
	flow_array.clear_flows();
}*/

/*
 * Send string of flows
 */
void send_message(string flowarray){
	size_t length = flowarray.size();
	uint32_t nlength = htonl(length);
	// First send message length
	send(client_fd, &nlength, 4, 0);
	send(client_fd, flowarray.c_str(), length, 0);
	// Prepare global variable for future use
	flow_string.clear();
	flow_string.append(flow_last);
}

/*
 * Standard method format to send a regular string
 */
void send_message_test(string str){
	size_t length = str.size();
	uint32_t nlength = htonl(length);
	send(client_fd, &nlength, 4, 0);
	send(client_fd, str.c_str(), length, 0);
}

void send_message(){
	send(client_fd, empty_buf, 4, 0);
}