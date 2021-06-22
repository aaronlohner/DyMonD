// Server side C/C++ program to demonstrate Socket programming
#include <server.hpp>

int server_fd, new_socket, valread;
struct sockaddr_in address;
int opt = 1;
int addrlen = sizeof(address);
char buffer[1024] = {0};
FlowArray flow_array = FlowArray();

int setup_server() {
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	printf("creating socket\n");
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
	// hence we use INADDR_ANY to specify the IP address
	address.sin_port = htons(PORT);
	
	printf("binding\n");
	// Forcefully attaching socket to the port 8080
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	printf("listening\n");
	if (listen(server_fd, 3) < 0)
	{
		perror("listen");
		exit(EXIT_FAILURE);
	}

	printf("waiting to accept...\n");
	if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0)
	{
		perror("accept");
		exit(EXIT_FAILURE);
	}
	printf("Connected.\n");
	
	// // Receive filter requests
	// receive_message();

	return 0;
}

void receive_message(char *inputBuffer) {
	printf("Waiting for a message from client...\n");
	int mesg_len_buf, mesg_length; //valread;
	// Only continue once message is received
	while (!valread) valread = recv(new_socket, &mesg_len_buf, 4, 0);
	mesg_length = ntohl(mesg_len_buf);
	//printf("Length: %d\n", mesg_length);
	recv(new_socket, inputBuffer, mesg_length, 0);
	printf("Received: %s\n", inputBuffer);
	valread = 0;
}

int add_to_flow_array(flow *flow) {
	Flow *flow_proto = flow_array.add_flows();

	flow_proto->set_s_addr(flow->saddr);
	flow_proto->set_s_port(flow->sport);
	flow_proto->set_d_addr(flow->daddr);
	flow_proto->set_d_port(flow->dport);
	flow_proto->set_num_bytes(flow->NumBytes/30);

	return 0;
}

int add_to_flow_array(flow *flow, double RST) {
	add_to_flow_array(flow);
	flow_array.mutable_flows(flow_array.flows_size()-1)->set_rst(RST);

	return 0;
}

int send_message(vector<struct flow*> flowarray){
	string data;
	flow_array.SerializeToString(&data);
	size_t length = data.size();
	uint32_t nlength = htonl(length);
	send(new_socket, &nlength, 4, 0);
	send(new_socket, data.c_str(), length, 0);
	printf("Flows sent to client\n");

	flow_array.clear_flows();

	return 0;
}