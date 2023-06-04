#include <arpa/inet.h>		// for inet_addr, bind, listen, accept, socket
#include <netinet/in.h>		// for structures relating to IPv4 addresses
#include <stdio.h>			// for print functions
#include <stdlib.h>			// for malloc, free, exit
#include <string.h>			// for strcpy, memset
#include <unistd.h>			// for read, write, close

#define BUFLEN 1024 // length of buffer to hold messages

// read response from server
void read_response (char *buf, int sockfd) 
{
	int i;
	char c;
	// read one byte at a time from server and put into buf
	for (c = '\0', i = 0; i < BUFLEN && c != '\n'; i++) {
		read(sockfd, &c, 1);
		buf[i] = c;
	}
	buf[i] = '\0';
}

int main ()
{
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	
	// fill out information about connection with server
	struct sockaddr_in serv_addr = {0}; 					// hold server address
	socklen_t serv_addr_len = sizeof(struct sockaddr_in);	// length of server's address in bytes
    serv_addr.sin_family = AF_INET;							// use IPv4 for address
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");		// specify server's IP address
    serv_addr.sin_port = htons(1234);						// specify server's listening socket port number
	
	connect(sockfd, (struct sockaddr *)&serv_addr, serv_addr_len); // make the call to connect
	
	// buffer for holding messages
	char *buf = (char *) malloc(sizeof(char) * BUFLEN);
	size_t max_len = BUFLEN; // need this for calling getline
	
	// for reading response from server
	char c;
	int i;
	
	// enter while loop to get input from terminal
	while (1) {
		// print a prompt to the terminal
		printf("-->  ");
		
		// get a line of input from the terminal (stdin)
		getline(&buf, &max_len, stdin);
		
		// send it to the server
		write(sockfd, buf, strlen(buf));
		
		// read response from server
		read_response(buf, sockfd);
		
		// print response to terminal
		printf("%s", buf);
	}
	
	// close the socket to initiate connection termination
	close(sockfd);
	
	// free the buffer
	free(buf);
	
	return 0;
}

