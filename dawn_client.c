#include <arpa/inet.h>		// for inet_addr, bind, listen, accept, socket
#include <netinet/in.h>		// for structures relating to IPv4 addresses
#include <stdio.h>			// for print functions
#include <stdlib.h>			// for malloc, free, exit
#include <string.h>			// for strcpy, memset
#include <unistd.h>			// for read, write, close
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define BUFLEN 1024 // length of buffer to hold messages

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

// Function to sign the data using the private key
int sign_data(const unsigned char* data, size_t data_len, const char* private_key_file, unsigned char** signature, size_t* signature_len) {
    FILE* private_key_file_ptr = fopen(private_key_file, "r");
    if (private_key_file_ptr == NULL) {
        fprintf(stderr, "Error opening private key file");
        return -1;
    }

    EVP_PKEY* private_key = PEM_read_PrivateKey(private_key_file_ptr, NULL, NULL, NULL);
    fclose(private_key_file_ptr);

    if (private_key == NULL) {
        fprintf(stderr, "Error reading private key\n");
        return -1;
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        fprintf(stderr, "Error creating EVP_MD_CTX\n");
        EVP_PKEY_free(private_key);
        return -1;
    }

    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, private_key) <= 0) {
        fprintf(stderr, "Error initializing signature\n");
        EVP_PKEY_free(private_key);
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }

    if (EVP_DigestSignUpdate(md_ctx, data, data_len) <= 0) {
        fprintf(stderr, "Error updating signature\n");
        EVP_PKEY_free(private_key);
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }

    if (EVP_DigestSignFinal(md_ctx, NULL, signature_len) <= 0) {
        fprintf(stderr, "Error determining signature buffer size\n");
        EVP_PKEY_free(private_key);
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }

    *signature = (unsigned char*)malloc(*signature_len);
    if (*signature == NULL) {
        fprintf(stderr, "Error allocating memory for signature\n");
        EVP_PKEY_free(private_key);
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }

    if (EVP_DigestSignFinal(md_ctx, *signature, signature_len) <= 0) {
        fprintf(stderr, "Error signing data\n");
        free(*signature);
        EVP_PKEY_free(private_key);
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }

    EVP_PKEY_free(private_key);
    EVP_MD_CTX_free(md_ctx);

    return 0;
}


// Generate public/private key pair for signing the password
int generate_key_pair(const char* private_key_file, const char* public_key_file) {
    EVP_PKEY* keypair = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!keypair || !ctx) {
        fprintf(stderr, "Error creating EVP_PKEY and EVP_PKEY_CTX\n");
        EVP_PKEY_free(keypair);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Error initializing key generation\n");
        EVP_PKEY_free(keypair);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        fprintf(stderr, "Error setting key size\n");
        EVP_PKEY_free(keypair);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_keygen(ctx, &keypair) <= 0) {
        fprintf(stderr, "Error generating RSA key pair\n");
        EVP_PKEY_free(keypair);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);

    // Save the private key
    FILE* private_key_fp = fopen(private_key_file, "w");
    if (!private_key_fp) {
        fprintf(stderr, "Error opening private key file for writing\n");
        EVP_PKEY_free(keypair);
        return -1;
    }

    if (!PEM_write_PKCS8PrivateKey(private_key_fp, keypair, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Error writing private key\n");
        fclose(private_key_fp);
        EVP_PKEY_free(keypair);
        return -1;
    }

    fclose(private_key_fp);

    // Save the public key
    FILE* public_key_fp = fopen(public_key_file, "w");
    if (!public_key_fp) {
        fprintf(stderr, "Error opening public key file for writing\n");
        EVP_PKEY_free(keypair);
        return -1;
    }

    if (!PEM_write_PUBKEY(public_key_fp, keypair)) {
        fprintf(stderr, "Error writing public key\n");
        fclose(public_key_fp);
        EVP_PKEY_free(keypair);
        return -1;
    }

    fclose(public_key_fp);
    EVP_PKEY_free(keypair);

    return 0;
}


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

    const char* private_key_file = "private_key.pem";
    const char* public_key_file = "public_key.pem";

    if (generate_key_pair(private_key_file, public_key_file) == 0) {
        printf("Public-private key pair generated successfully\n");
    } else {
        printf("Failed to generate key pair\n");
    }

    char* public_key = (char*)malloc(sizeof(char) * BUFLEN);
    size_t max_len = BUFLEN;
    FILE* publicKeyFile;

    if (read(sockfd, public_key, max_len) == -1) {
        printf("error: %s\n", strerror(errno));
        fflush(stdout);
    }

    printf("public_key: %s\n", public_key);
    send_ack(sockfd);

    write(sockfd, public_key, strlen(public_key));
    receive_ack(sockfd);

    publicKeyFile = fopen("publicKey.pem", "w+");
    fwrite(public_key, sizeof(char), strlen(public_key), publicKeyFile);
    fclose(publicKeyFile);

    const char* password = "myteamisgreat";

    char* encrypted_password;
    unsigned char* signature;
    size_t signature_len;

    if (encrypt_password(password, &encrypted_password) == 0) {
        printf("encrypted_password: %s\n", encrypted_password);

        write(sockfd, encrypted_password, strlen(encrypted_password)); // Write the encrypted data
        receive_ack(sockfd);
    }

    if (sign_data((const unsigned char*) password, strlen(password), private_key_file, &signature, &signature_len) == 0) {
        printf("Signature generated successfully\n");
        printf("generated signature: %s\n", signature);

        write(sockfd, signature, strlen(signature));
        receive_ack(sockfd);
    }

    // Close the socket to initiate connection termination
    close(sockfd);

    // Free the buffer
    free(public_key);
    free(encrypted_password);
    free(signature);

    return 0;
}

