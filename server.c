#include <arpa/inet.h>		// for inet_addr, bind, listen, accept, socket
#include <netinet/in.h>		// for structures relating to IPv4 addresses
#include <stdio.h>			// for print functions
#include <stdlib.h>			// for malloc, free, exit
#include <string.h>			// for strcpy, memset
#include <unistd.h>			// for read, write, close
#include <time.h>			// for time functions
#include <ctype.h>			// for toupper
#include "security.h"

#define BUFLEN 1024 // define buffer length

// define request types
#define ECHO 0
#define TIME 1
#define TEMP 2
#define UNDEF -1
#define CLI_DEAD -2 // when client dies

// receive request from client and return the message type
int receive_request (char *buf, int connfd)
{
	// read until newline from connfd
	char c = '\0';
	int i = 0, ret;
	for ( ; i < BUFLEN && c != '\n'; i++) {
		ret = read(connfd, &c, 1); // read one byte
		
		// if read returned 0 bytes read, we've reached "end-of-file" i.e. client is dead
		if (ret == 0) { 
			return CLI_DEAD;
		}
		buf[i] = c;
	}
	buf[i] = '\0'; // terminating null
	
	// determine the message type
	if (strncmp(buf, "echo", 4) == 0) {
		return ECHO;
	} else if (strncmp(buf, "time", 4) == 0) {
		return TIME;
	} else if (strncmp(buf, "temp", 4) == 0) {
		return TEMP;
	} else {
		return UNDEF;
	}
}

// send reply to client according to request type
void send_reply (int request_type, char *buf, int connfd) 
{
	char send_buf[BUFLEN]; // buffer for sending messages to client
	
	if (request_type == ECHO) {
		// copy the message after the "echo" into the send_buf
		sprintf(send_buf, "%s", buf + strlen("echo") + 1);
	} else if (request_type == TIME) {
		// get the time and printinto send_buf
		time_t rawtime;
		struct tm * timeinfo;
		time(&rawtime);
		timeinfo = localtime(&rawtime);
		sprintf(send_buf, "%s", asctime(timeinfo));
	} else if (request_type == TEMP) {
		// get the temperature and scale of the input
		double input_temp = atof(buf + strlen("temp") + 1);
		char input_scale = toupper(buf[strlen(buf) - 2]); // this is either 'F' or 'C'
		
		// print the converted temperature into send_buf
		if (input_scale == 'F') {
			sprintf(send_buf, "%.2f C\n", (input_temp - 32.0) * 0.5556);
		} else if (input_scale == 'C') {
			sprintf(send_buf, "%.2f F\n", (input_temp * 1.8) + 32.0);
		} else {
			sprintf(send_buf, "Unknown temperature scale\n");
		}
	} else {
		sprintf(send_buf, "Unknown request type\n");
	}
	
	// send the message
	write(connfd, send_buf, strlen(send_buf));
}

int main () 
{
	initialize_BIO();
	char* public_key = "myteamisgreat";
	create_public_key(&public_key_string); // Generates public/private key pair. Stores the private key in BIO.

	int sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	int connfd; // socket that talks to client
	
	// prepare to call bind
	struct sockaddr_in serv_addr = {0};						// hold server address
	struct sockaddr_in cli_addr =  {0};						// hold client address 
	socklen_t cli_addr_len = sizeof(struct sockaddr_in); 	// length of requesting client's address in bytes
	serv_addr.sin_family  =  AF_INET;						// use  IPv4  
	serv_addr.sin_addr.s_addr  = htonl(INADDR_ANY);			// use any IP interface
	serv_addr.sin_port = htons(1234);						// assign a port number
	
	// call to bind, then set to listening mode
	bind(sockfd, (struct sockaddr*) &serv_addr, sizeof(struct sockaddr_in));
	listen(sockfd, 2);
	
	// allocate buffer for receiving messages from client
	char *buf = (char *) malloc(sizeof(char) * BUFLEN);
	
	// holds received request type
	int request_type;
	
	// enter infinite loop to connect with consecutive clients
	while (1) {
		// wait for client to request connection with server
		connfd = accept(sockfd, (struct sockaddr*) &cli_addr, &cli_addr_len);
		
		// enter another infinite loop that breaks when client disconnects
		while (1) {
			// send asymmetric public key from the public/private key pair to Dawn so Dawn can use it encrypt its password
			// if public key not equal, immediately disconnect 

			// get a request from the client
			request_type = receive_request(buf, connfd);
		
			if (request_type == CLI_DEAD) {
				break;
			}
		
			// send reply to client
			send_reply(request_type, buf, connfd);
		}
		close(connfd); // close the socket talking with the client
		
	}
	
	// close the listening socket
	close(sockfd);
	
	// free the buffer
	free(buf);
	
	return 0; 
}
