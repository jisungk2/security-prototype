#include <stdio.h>			// for print functions
#include <stdlib.h>			// for malloc, free, exit
#include <string.h>			// for strcpy, memset
#include <unistd.h>			// for read, write, close
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <errno.h>

int rsaEncrypt(const char* publicKeyFile, const char* password, unsigned char** encryptedData, size_t* encryptedDataLength) {
    FILE* publicKey = fopen(publicKeyFile, "r");
    if (!publicKey) {
        printf("Failed to open public key file.\n");
        return 0;
    }

	RSA* t = RSA_new();

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

int main() {
	const char* pKeyFileName = "publicKey.pem";
	const char* password = "myteamisgreat";

	unsigned char* encryptedData;
	size_t encryptedDataLength;

	if (rsaEncrypt(pKeyFileName, password, &encryptedData, &encryptedDataLength)) {
        char* hex_data = malloc((2 * EVP_MD_size(EVP_sha256()) + 1) * sizeof(char));
        for (int i = 0; i < EVP_MD_size(EVP_sha256()); i++) {
            sprintf(&hex_data[i * 2], "%02x", encryptedData[i]);
        }
        hex_data[2 * EVP_MD_size(EVP_sha256())] = '\0';
        printf("encrypted data in hex: %s\n", hex_data);

		printf("Encrypted password:\n");
		for (size_t i = 0; i < encryptedDataLength; ++i) {
			printf("%02x", encryptedData[i]);
		}
		printf("\n");

		free(encryptedData);
	}
}