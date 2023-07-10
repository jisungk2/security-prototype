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

// Function to send acknowledgment to the client
int send_ack(int connfd) {
    const char* ack_msg = "ACK";
    if (write(connfd, ack_msg, strlen(ack_msg)) == -1) {
        fprintf(stderr, "Error sending acknowledgment\n");
        return -1;
    }
	printf("sent acknowledgment: %s\n", ack_msg);
    return 0;
}

// Function to receive acknowledgment from the server
int receive_ack(int connfd) {
    char ack_buf[BUFLEN];
    memset(ack_buf, 0, BUFLEN);
    ssize_t bytes_read = read(connfd, ack_buf, BUFLEN - 1);
    if (bytes_read == -1) {
        fprintf(stderr, "Error receiving acknowledgment\n");
        return -1;
    }
    ack_buf[bytes_read] = '\0';

    if (strcmp(ack_buf, "ACK") != 0) {
        fprintf(stderr, "Error: Invalid acknowledgment received\n");
        return -1;
    }
	printf("received acknowledgment: %s\n", ack_buf);
    return 0;
}

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
	char* encrypted_message = malloc(sizeof(char) * BUFLEN);
	char* received_public_key = malloc(sizeof(char) * BUFLEN);
	char* received_signature = malloc(sizeof(char) * BUFLEN);
	
	// wait for client to request connection with server
	connfd = accept(sockfd, (struct sockaddr*) &cli_addr, &cli_addr_len);
		
	// send asymmetric public key from the public/private key pair to Dawn so Dawn can use it to encrypt its password
	// if public key not equal, immediately disconnect. <- Will be much more difficult than it seems because I need to understand protobuf
	write(connfd, public_key_string, strlen(public_key_string));

	receive_ack(connfd);

	// read the public key that dawn sent back to runtime
	ssize_t bytes_read = read(connfd, received_public_key, BUFLEN);
	send_ack(connfd);
	if (bytes_read > 0) {
		received_public_key[bytes_read] = '\0'; // Null-terminate the received data
		printf("received_public_key: %s\n", received_public_key);
	} else {
		printf("Error reading from the client\n");
	}

	// read the encrypted message that dawn sent to runtime 
	bytes_read = read(connfd, encrypted_message, BUFLEN);
	send_ack(connfd);
	if (bytes_read > 0) {
		encrypted_message[bytes_read] = '\0'; // Null-terminate the received data
		printf("encrypted_message: %s\n", encrypted_message);
	} else {
		printf("Error reading from the client\n");
	}

	// read the signature that dawn sent to runtime
	bytes_read = read(connfd, received_signature, BUFLEN);
	send_ack(connfd);
	if (bytes_read > 0) {
		received_signature[bytes_read] = '\0'; // Null-terminate the received data
		printf("received_signature: %s\n", received_signature);
	} else {
		printf("Error reading from the client\n");
	}

	char* decrypted_message;
	char* salted_message;
	
	// decrypted the received encrypted message using the saved private key
	if (decrypt_login_info((unsigned char*) encrypted_message, strlen(encrypted_message), &decrypted_message) == 0) {
		printf("Decrypted Password: %s\n", decrypted_message);
		salt_string(decrypted_message, &salted_message); // salt the decrypted password
		printf("salted: %s\n", salted_message);
	}

	unsigned char* hashed_salted_message;

	// create hash from salted string
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

		// compare hash value stored in disk and hash value created from received encrypted password 
		// compare public key sent from runtime to dawn and public key sent from dawn to runtime
		if (strcmp(buffer, hex_hash) == 0 && strcmp(public_key_string, received_public_key) == 0) {
			printf("Hashed value and received public key match!\n");
		} else {
			printf("Failed Connection!\n");
		}

		const char* public_key_file = "public_key.pem";

		// verify the signature that is sent from dawn to runtime using the public key that matches the private key that dawn used to sign its password
		if (verify_signature((const unsigned char*) decrypted_message, strlen(decrypted_message), (const unsigned char*) received_signature, strlen(received_signature), public_key_file) == 1) {
			printf("Valid signature!\n");
		} else {
			printf("Invalid signature!\n");
		}

		// free the buffer
		free(public_key_string);
		free(salted_message);
		free(decrypted_message);
		free(hex_hash);
		free(encrypted_message);
		free(received_public_key);
		free(received_signature);
		OPENSSL_free(hashed_salted_message);
    } else {
        printf("Hashing failed.\n");
    } 

	close(connfd); // close the socket talking with the client
		
	// close the listening socket
	close(sockfd);
	
	return 0; 
}
