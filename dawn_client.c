#include <arpa/inet.h>		// for inet_addr, bind, listen, accept, socket
#include <netinet/in.h>		// for structures relating to IPv4 addresses
#include <stdio.h>			// for print functions
#include <stdlib.h>			// for malloc, free, exit
#include <string.h>			// for strcpy, memset
#include <unistd.h>			// for read, write, close
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "security.c"

#define BUFLEN 1024 // length of buffer to hold messages

// Function to encrypt the password using RSA algorithm
int rsaEncrypt(const char* publicKeyFile, const char* password, unsigned char** encryptedData, size_t* encryptedDataLength) {
    FILE* publicKey = fopen(publicKeyFile, "r");
    if (!publicKey) {
        printf("Failed to open public key file.\n");
        return 0;
    }

    RSA* rsaKey = PEM_read_RSA_PUBKEY(publicKey, NULL, NULL, NULL);
    if (!rsaKey) {
        printf("Failed to read public key.\n");
        fclose(publicKey);
        return 0;
    }

    int rsaKeySize = RSA_size(rsaKey);
    *encryptedData = (unsigned char*)malloc(rsaKeySize);
    *encryptedDataLength = RSA_public_encrypt(strlen(password), (unsigned char*)password, *encryptedData, rsaKey, RSA_PKCS1_PADDING);

    RSA_free(rsaKey);
    fclose(publicKey);

    if (*encryptedDataLength == -1) {
        printf("Failed to encrypt the password.\n");
        free(*encryptedData);
        return 0;
    }

    return 1;
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
	char *public_key = (char *) malloc(sizeof(char) * BUFLEN);
	size_t max_len = BUFLEN; // need this for calling getline
	FILE* publicKeyFile;
	
	// enter while loop to get input from terminal
	while (1) {
		read(sockfd, public_key, max_len);
		printf("public_key: %s", public_key);

		publicKeyFile = fopen("publicKey.pem", "w+");

		fwrite(public_key, sizeof(char), sizeof(public_key), publicKeyFile);

		const char* pKeyFileName = "publicKey.pem";
		const char* password = "myteamisgreat";

		unsigned char* encryptedData;
    	size_t encryptedDataLength;

	    if (rsaEncrypt(pKeyFileName, password, &encryptedData, &encryptedDataLength)) {
        	printf("Encrypted password:\n");
        	for (size_t i = 0; i < encryptedDataLength; ++i) {
            	printf("%02x", encryptedData[i]);
        	}
        	printf("\n");

        	free(encryptedData);
    	}

	}

	fclose(publicKeyFile);
	
	// close the socket to initiate connection termination
	close(sockfd);
	
	// free the buffer
	free(public_key);
	
	return 0;
}

