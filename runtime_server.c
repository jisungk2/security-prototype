#include <arpa/inet.h>		// for inet_addr, bind, listen, accept, socket
#include <netinet/in.h>		// for structures relating to IPv4 addresses
#include <stdio.h>			// for print functions
#include <stdlib.h>			// for malloc, free, exit
#include <string.h>			// for strcpy, memset
#include <unistd.h>			// for read, write, close
#include <time.h>			// for time functions
#include <ctype.h>			// for toupper
#include "security.c"

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
	char* received_message = malloc(sizeof(char) * BUFLEN);
	
	// holds received request type
	int request_type;
	
	// enter infinite loop to connect with consecutive clients
		// wait for client to request connection with server
	connfd = accept(sockfd, (struct sockaddr*) &cli_addr, &cli_addr_len);
		
		// enter another infinite loop that breaks when client disconnects
			// send asymmetric public key from the public/private key pair to Dawn so Dawn can use it encrypt its password
			// if public key not equal, immediately disconnect. <- Will be much more difficult than it seems because I need to understand protobuf
	write(connfd, public_key_string, strlen(public_key_string));

	//read(connfd, encrypted_message, strlen((char *)encrypted_message));

	// After reading from the client
	ssize_t bytes_read = read(connfd, received_message, BUFLEN);
	if (bytes_read > 0) {
		received_message[bytes_read] = '\0'; // Null-terminate the received data
		printf("received_message: %s\n", received_message);
	} else {
		printf("Error reading from the client\n");
	}

	char received_public_key[BUFLEN];
	strncpy(received_public_key, received_message, strlen(public_key_string));
	received_public_key[strlen(public_key_string)] = '\0';
	printf("received_public_key: %s\n", received_public_key);

	char* encrypted_message = malloc(sizeof(char) * BUFLEN);
	strncpy(encrypted_message, received_message + strlen(public_key_string), BUFLEN);
	printf("encrypted_message: %s\n", encrypted_message);

	char* decrypted_message;
	char* salted_message;
	
	if (decrypt_login_info((unsigned char*) encrypted_message, strlen(encrypted_message), &decrypted_message) == 0) {
		printf("Decrypted Password: %s\n", decrypted_message);
		salt_string(decrypted_message, &salted_message);
		printf("salted: %s\n", salted_message);
		free(decrypted_message);
	}

	unsigned char* hashed_salted_message;
    if (hash_message(salted_message, &hashed_salted_message) == 0) {
    // Convert binary hash to hexadecimal string representation
    char* hex_hash = malloc((2 * EVP_MD_size(EVP_sha256()) + 1) * sizeof(char));
    for (int i = 0; i < EVP_MD_size(EVP_sha256()); i++) {
        sprintf(&hex_hash[i * 2], "%02x", hashed_salted_message[i]);
    }
    hex_hash[2 * EVP_MD_size(EVP_sha256())] = '\0';

    printf("Hashed Salted Message (Hex): %s\n", hex_hash);

	FILE* file = fopen("hashed.txt", "r");
    char buffer[BUFLEN];
    if (fgets(buffer, sizeof(buffer), file) == NULL) {
        printf("Error reading the string from the file.\n");
        fclose(file);
        return 1;
    }
	fclose(file);
	if (strcmp(buffer, hex_hash) == 0 && strcmp(public_key_string, received_public_key) == 0) {
		printf("Successful Connection!\n");
	} else {
		printf("Failed Connection!\n");
	}

    free(hex_hash);
    OPENSSL_free(hashed_salted_message);
    } else {
        printf("Hashing failed.\n");
    } 
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
	close(connfd); // close the socket talking with the client
		
	
	// close the listening socket
	close(sockfd);
	
	// free the buffer
	free(received_message);
	
	return 0; 
}
