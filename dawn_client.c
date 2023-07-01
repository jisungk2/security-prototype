#include <arpa/inet.h>		// for inet_addr, bind, listen, accept, socket
#include <netinet/in.h>		// for structures relating to IPv4 addresses
#include <stdio.h>			// for print functions
#include <stdlib.h>			// for malloc, free, exit
#include <string.h>			// for strcpy, memset
#include <unistd.h>			// for read, write, close
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <errno.h>

#define BUFLEN 1024 // length of buffer to hold messages

// Function to encrypt the password using RSA algorithm
int encrypt_password(const char* password, char** encrypted_password) {
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* public_key = NULL;

    FILE* public_key_file = fopen("publicKey.pem", "r");
    if (public_key_file == NULL) {
        fprintf(stderr, "Error opening public key file");
        return -1;
    }

    public_key = PEM_read_PUBKEY(public_key_file, NULL, NULL, NULL);
    fclose(public_key_file);

    if (public_key == NULL) {
        fprintf(stderr, "Error reading public key\n");
        return -1;
    }

    ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "Error creating EVP_PKEY_CTX\n");
        EVP_PKEY_free(public_key);
        return -1;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        fprintf(stderr, "Error initializing encryption\n");
        EVP_PKEY_free(public_key);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        fprintf(stderr, "Error setting RSA padding\n");
        EVP_PKEY_free(public_key);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    size_t password_len = strlen(password);
    size_t encrypted_password_len;
    *encrypted_password = NULL;

    if (EVP_PKEY_encrypt(ctx, NULL, &encrypted_password_len, (const unsigned char*)password, password_len) <= 0) {
        fprintf(stderr, "Error determining encrypted password buffer size\n");
        EVP_PKEY_free(public_key);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    *encrypted_password = (char*)malloc(encrypted_password_len);
    if (*encrypted_password == NULL) {
        fprintf(stderr, "Error allocating memory for encrypted password\n");
        EVP_PKEY_free(public_key);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx, (unsigned char*)*encrypted_password, &encrypted_password_len, (const unsigned char*)password, password_len) <= 0) {
        fprintf(stderr, "Error encrypting password\n");
        free(*encrypted_password);
        EVP_PKEY_free(public_key);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_free(public_key);
    EVP_PKEY_CTX_free(ctx);

    return 0;
}


int main() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // fill out information about connection with server
    struct sockaddr_in serv_addr = {0};
    socklen_t serv_addr_len = sizeof(struct sockaddr_in);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(1234);

    connect(sockfd, (struct sockaddr*)&serv_addr, serv_addr_len);

    char* public_key = (char*)malloc(sizeof(char) * BUFLEN);
    size_t max_len = BUFLEN;
    FILE* publicKeyFile;

    if (read(sockfd, public_key, max_len) == -1) {
        printf("error: %s\n", strerror(errno));
        fflush(stdout);
    }

    publicKeyFile = fopen("publicKey.pem", "w+");
    fwrite(public_key, sizeof(char), strlen(public_key), publicKeyFile);
    fclose(publicKeyFile);

    const char* password = "myteamisgreat";

    char* encrypted_password;

    if (encrypt_password(password, &encrypted_password) == 0) {
        printf("encrypted_password: %s\n", encrypted_password);

        write(sockfd, encrypted_password, strlen(encrypted_password)); // Write the encrypted data
    }

    // Close the socket to initiate connection termination
    close(sockfd);

    // Free the buffer
    free(public_key);
    free(encrypted_password);

    return 0;
}

