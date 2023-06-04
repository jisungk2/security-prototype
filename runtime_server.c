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
#define UNDEF -1
#define CLI_DEAD -2 // when client dies

int main () 
{
	initialize_BIO();
	char* public_key_string;
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
			// if public key not equal, immediately disconnect. <- Will be much more difficult than it seems because I need to understand protobuf
			write(sockfd, public_key, strlen(public_key));
			/* 
			Receive from Dawn -> Runtime: signed + encrypted password + public key to use for verification
			-> char* encrypted message

			if (strcmp(received public_key, public_key) != 0) {
				text protobuf we have received connection request from invalid machine
				break;
			} 

			char* decrypted_message
			decrypt_login_info(encrypted_message, decrypted_message);

			char* salted_message;
			salt_string(decrypted_message, &salted_message);

			unsigned char* hashed_salted_message;
			hash_message(salted_message, &hashed_salted_message);

			if (compare_hashed_password(hashed_salted_message) == 0) {
				printf("valid pasword!");
				continue with connected dawn
			} else {
				text protobuf for invalid password
				break;
			}
			*/

		}
		close(connfd); // close the socket talking with the client
		
	}
	
	// close the listening socket
	close(sockfd);
	
	// free the buffer
	free(buf);
	
	return 0; 
}
