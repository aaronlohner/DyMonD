// Server side C/C++ program to demonstrate Socket programming
#include <server.hpp>
// #include <sniffed_info.pb.h>

int server_fd, new_socket, valread;
struct sockaddr_in address;
int opt = 1;
int addrlen = sizeof(address);
char buffer[1024] = {0};

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
	return 0;
}

int send_message(/*vector<flow &> flowElement*/Flow &flow){
	string data;
	flow.SerializeToString(&data);
	size_t length = data.size();
	uint32_t nlength = htonl(length);
	send(new_socket, &nlength, 4, 0);
	send(new_socket, data.c_str(), length, 0);
	printf("Serialized message sent\n");

	return 0;
}

// int main(int argc, char const *argv[])
// {	
// 	return 0;
// }