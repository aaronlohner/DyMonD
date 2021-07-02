#include <server.hpp>

int server_fd, client_fd, valread;
struct sockaddr_in address;
int opt = 1;
int addrlen = sizeof(address);
char buffer[1024] = {0};
FlowArray flow_array = FlowArray();

/*
 * Set up server socket and wait for client to connect
 */
void setup_server() {
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	// Creating socket file descriptor
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		perror("socket failed");
		exit(EXIT_FAILURE);
	}
	
	// Forcefully attaching socket to the port 8080
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
	{
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;// we bind the server to the localhost,
	// hence we use INADDR_ANY to allow any client IP address
	address.sin_port = htons(PORT); // defined as 8080
	
	// Forcefully attaching socket to the port 8080
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

	printf("Waiting for client to accept...\n");
	if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0)
	{
		perror("accept");
		exit(EXIT_FAILURE);
	}
	printf("Connected.\n");
}

/*
 * Close the socket conection with client
 */
void stop_server(){
	close(client_fd);
	printf("Server disconnected from client\n");
}

/*
 * Read incoming message into input buffer
 */
void receive_message(char *inputBuffer) {
	printf("Waiting for a message from client...\n");
	int mesg_len_buf, mesg_length;
	
	// Expect to receive message length first in a 4-byte block immediate followed by the message
	// Only continue once message is received
	while (!valread) valread = recv(client_fd, &mesg_len_buf, 4, 0);
	mesg_length = ntohl(mesg_len_buf);
	
	recv(client_fd, inputBuffer, mesg_length, 0);
	printf("Received: %s\n", inputBuffer);
	// Reset global variable for future incoming messages
	valread = 0;
}

/*
 * Add flow element to flow array
 */
void add_to_flow_array(flow *flow) {
	// Create a Flow protobuf object
	Flow *flow_proto = flow_array.add_flows();
	
	// Populate fields of protobuf Flow with fields from the inputted flow struct fields
	flow_proto->set_s_addr(flow->saddr);
	flow_proto->set_s_port(flow->sport);
	flow_proto->set_d_addr(flow->daddr);
	flow_proto->set_d_port(flow->dport);
	flow_proto->set_num_bytes(flow->NumBytes/30);
}

/*
 * Add flow element to flow array with RST
 */
void add_to_flow_array(flow *flow, double RST) {
	add_to_flow_array(flow);
	flow_array.mutable_flows(flow_array.flows_size()-1)->set_rst(RST);
}

/*
 * Send array of flows to client
 */
void send_message(vector<struct flow*> flowarray){
	string data;
	flow_array.SerializeToString(&data);
	size_t length = data.size();
	uint32_t nlength = htonl(length);
	// First send message length
	send(client_fd, &nlength, 4, 0);
	send(client_fd, data.c_str(), length, 0);
	printf("Flows sent to client\n");
	// Reset flow_array global variable for future use
	flow_array.clear_flows();
}