#include "security.h"

#define HASHLEN 32
#define BUFLEN 2048

// BIO's are OPENSSL's own implementation of I/O channels. Used in this case to store the private key in a temporary spot without needing to write out to a file
BIO* mem = NULL;

int initialize_BIO() {
    if (mem == NULL) {
        mem = BIO_new(BIO_s_mem());
        if (mem == NULL) {
            return -1;
        }
    }
    return 0;
}

//signature. Person who sends message. Creates random public/private key. public_key_string points to the public key
int create_public_key(char* public_key_string) {
    EVP_PKEY_CTX* ctx;      // context holding info related to public key encryption
    EVP_PKEY* pkey = NULL;  // public key from a private/public key pair

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // allocates public key algorithm context using the key type
    if (ctx == NULL) {
        return -1;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) { // key generation operation
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) { //RSA key length of 2048 bits
        return -1;
    }

    /* Generate key */
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { //generated key written to pkey
        return -1;
    }
    // store the private key in OPENSSL's temporary memory buffer
    PEM_write_bio_PrivateKey(mem, pkey, NULL, NULL, 0, 0, NULL); // private key stored in mem created earlier

    //write the public key to the .pem file
    FILE* public_key_file = fopen("keys.pem", "w+");

    PEM_write_PUBKEY(public_key_file, pkey);

    fseek(public_key_file, 0, SEEK_SET);

    char ignore_line[256];
    int line_count = 0;
    while (fgets(ignore_line, sizeof(ignore_line), public_key_file) != NULL) {
        line_count++;
    }

    fseek(public_key_file, 0, SEEK_SET);
    char line[256];
    if (fgets(line, sizeof(line), public_key_file) == NULL) {
        printf("File is empty.\n");
        fclose(public_key_file);
        return 1;
    }
    
    int count = 0;
    // Read and store the lines until the last line
    while (fgets(line, sizeof(line), public_key_file) != NULL && count < line_count - 2) {
        // Remove the trailing newline character
        line[strcspn(line, "\n")] = '\0';

        // Append the line to the content variable
        strcat(public_key_string, line);
        count += 1;
    }

    // Remove the trailing newline character at the end
    public_key_string[strlen(public_key_string)] = '\0';

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    fclose(public_key_file);
    return 0;
}

//decrypted message using private key stored in char* decrypted message
int decrypt_login_info(char* encrypted_message, char* decrypted_message) {
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* private_key = NULL;

    private_key = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);

    if (private_key == NULL) {
        return -1;
    }

    ctx = EVP_PKEY_CTX_new(private_key, NULL);

    if (ctx == NULL) {
        return -1;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        return -1;
    }

    unsigned char* decryption_buffer;
    size_t decryption_buffer_len;
    size_t encrypted_message_len = strlen(encrypted_message);

    if (EVP_PKEY_decrypt(ctx, NULL, &decryption_buffer_len, (unsigned char*) encrypted_message, encrypted_message_len) <= 0) {
        return -1;
    }

    decryption_buffer = OPENSSL_malloc(decryption_buffer_len);

    if (decryption_buffer == NULL) {
        return -1;
    }

    //error here!
    if (EVP_PKEY_decrypt(ctx, decryption_buffer, &decryption_buffer_len, (unsigned char*) encrypted_message, encrypted_message_len) <= 0) {
        printf("error\n");
        return -1;
    }

    decrypted_message = malloc(decryption_buffer_len);

    for (int i = 0; i < decryption_buffer_len - 1; i++) {
        (decrypted_message)[i] = (char) *(decryption_buffer + i);
    }

    (decrypted_message)[decryption_buffer_len - 1] = '\0';

    OPENSSL_free(decrypted_message);
    EVP_PKEY_free(private_key);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

//Read the string from salt.txt and add to the back of the message
int salt_string(char* message, char** salted_message) {
    FILE* salt_file = fopen("salt.txt", "r");
    char buf[BUFLEN];
    fgets(buf, BUFLEN, salt_file);

    int salt_len = strlen(buf);
    int message_length = strlen(message);
    
    *salted_message = malloc(salt_len + message_length + 1);
    if (*salted_message == NULL) {
        return -1;
    }
    for (int i = 0; i < message_length; i++) {
        (*salted_message)[i] = message[i];
    }
    for (int i = message_length; i < message_length + salt_len; i++) {
        (*salted_message)[i] = buf[i - message_length];
    }
    fclose(salt_file);
    return 0;
}

char* generateRandomString(int size) {
    char* randomString = malloc((size + 1) * sizeof(char)); // Allocate memory for the string (+1 for null terminator)
    const char characters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; // Pool of characters
    
    srand(time(NULL)); // Initialize the random number generator
    
    for (int i = 0; i < size; i++) {
        int randomIndex = rand() % (sizeof(characters) - 1); // Generate a random index within the character pool
        randomString[i] = characters[randomIndex]; // Select a random character
    }
    
    randomString[size] = '\0'; // Null-terminate the string
    
    return randomString;
}

//Uses generateRandomString to create salt string that is 32 - message_length and stores it in salt.txt
int create_salt_string(char* message) {
    FILE* salt_file = fopen("salt.txt", "w+");
    int message_length = strlen(message);

    char* salt_string = generateRandomString(HASHLEN - message_length);
    fwrite(salt_string, sizeof(char), HASHLEN - message_length, salt_file);

    free(salt_string);
    fclose(salt_file);
    return 0;
}


//hash function tries to create hash string of length 256 but my string in hashed.txt is shorter than 256 so it adds garbage at the end
int hash_message(char* salted_message, unsigned char** hashed_salted_message) {
    EVP_MD_CTX* hash_ctx = NULL;
    hash_ctx = EVP_MD_CTX_new();
    if (EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL) != 1) {
        return -1;
    }
    *hashed_salted_message = OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
    if (*hashed_salted_message == NULL) {
        OPENSSL_free(*hashed_salted_message);
        return -1;
    }
    if (EVP_DigestUpdate(hash_ctx, salted_message, strlen(salted_message)) == 0) {
        return -1;
    }
    unsigned int max_hashed_len = EVP_MD_size(EVP_sha256());
    if (EVP_DigestFinal_ex(hash_ctx, *hashed_salted_message, &max_hashed_len) == 0) {
        return -1;
    }
    EVP_MD_CTX_destroy(hash_ctx);
    return 0;
}


//compare the hash+salt message received with the hash+salt message stored in raspi
int compare_hashed_password(char* hashed_salted_message) {
    FILE* hashed_on_pi;
    hashed_on_pi = fopen("hashed.txt", "r");
    if (hashed_on_pi == NULL) {
        fclose(hashed_on_pi);
        return -1;
    }
    fseek(hashed_on_pi, 0L, SEEK_END);
    int bufsize = ftell(hashed_on_pi);
    fseek(hashed_on_pi, 0L, SEEK_SET);
    char hashed_pass[bufsize];
    size_t newLen = fread(hashed_pass, sizeof(char), bufsize, hashed_on_pi);
    hashed_pass[newLen++] = '\0';
    return strcmp(hashed_pass, hashed_salted_message);
}

//print the hashed binary data in a hexadecimal representation so we can put null terminator at the end
char* printable_hash(unsigned char* hashed_salted_message) {
    char* hex_hash = malloc((2 * EVP_MD_size(EVP_sha256()) + 1) * sizeof(char));
    for (int i = 0; i < EVP_MD_size(EVP_sha256()); i++) {
        sprintf(&hex_hash[i * 2], "%02x", hashed_salted_message[i]);
    }
    hex_hash[2 * EVP_MD_size(EVP_sha256())] = '\0';

    return hex_hash;
}

int main() {
    BIO_reset(mem);
    initialize_BIO();
    char public_key_string[500] = "";
    char* salted_message;

    create_public_key(public_key_string);
    printf("public key: %s\n", public_key_string);

    FILE* pem_file = fopen("keys.pem", "r");
    EVP_PKEY* public_key = PEM_read_PUBKEY(pem_file, NULL, NULL, NULL);
    fclose(pem_file);

    PEM_read_bio_PrivateKey(mem, &public_key, NULL, NULL);
    FILE* private_key_file = fopen("private.pem", "w+");
    PEM_write_PrivateKey(private_key_file, public_key, NULL, NULL, 0, NULL, NULL);


    char* team_password = "myteamisgreat";
    //create_salt_string(team_password); //Create salt string at the beginning so when we create password + salt, it is exactly 32 chars length and is randomized
    salt_string(team_password, &salted_message);
    printf("salted: %s\n", salted_message);

    unsigned char* hashed_salted_message;

    hash_message(salted_message, &hashed_salted_message);
    printf("hashed: %s\n", hashed_salted_message);

    char* hashed_salted = printable_hash(hashed_salted_message);
    printf("Hashed Salted Message (Hex): %s\n", hashed_salted);

    free(hashed_salted);
    OPENSSL_free(hashed_salted_message);
    

    // if (hash_message(salted_message, &hashed_salted_message) == 0) {
    // // Convert binary hash to hexadecimal string representation
    // char* hex_hash = malloc((2 * EVP_MD_size(EVP_sha256()) + 1) * sizeof(char));
    // for (int i = 0; i < EVP_MD_size(EVP_sha256()); i++) {
    //     sprintf(&hex_hash[i * 2], "%02x", hashed_salted_message[i]);
    // }
    // hex_hash[2 * EVP_MD_size(EVP_sha256())] = '\0';

    // printf("Hashed Salted Message (Hex): %s\n", hex_hash);

    // free(hex_hash);
    // OPENSSL_free(hashed_salted_message);
    // } else {
    //     printf("Hashing failed.\n");
    // } 


    // hash_message(salted_message, &hashed_salted_message);

    // printf("hashed: %s\n", hashed_salted_message);

    //create_public_key(public_key);

    //char* encrypted_message = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApkj48t8AGXNMhL6O4jaIXK9kPTlH1Ydl1UmlIMVNp5XmzzU3fEBQpG5/eJ2Mz6C2G3VH0G40SeayWSqwRmaTe0sHIsL1hb6Xb7E3cj8LibHaYljMi/IZJ4TEnCE1PIt9eVTtqKaxRFBvNYo2mqbz+kH9c+UzqhxVP0d8LT+p9Jfito1fP/NZoYNOcDwbgJ0VwmfK3Hno+Y5HLvsEMBdRfq43xscwhcLcghx0NU44mvrSvJE/Z/Moq8xId0Q+y7POrh+IpX9A6Uer955OeTZ0w/nAMUO8VR55Eu+iXV+k/uTgmHI+ygE0RnnRkUiyu8wadvl9e25aXZC7zD2duTqDHwIDAQAB";

    //char* encrypted_message = "myteamisgreat";
    //char* decrypted;

    //decrypt_login_info(encrypted_message, decrypted);

    return 0;
}