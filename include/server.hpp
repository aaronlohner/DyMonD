#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sniffed_info.pb.h>
#include <string>
using namespace std;

#define PORT 8080
extern int server_fd, new_socket, valread;
extern struct sockaddr_in address;
extern int opt;
extern int addrlen;
extern char buffer[1024];

int setup_server();

int send_message(Flow &finfo);