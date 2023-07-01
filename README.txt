COMMAND TO COMPILE SECURITY.C:
gcc security.c \
    -o security \
    -I /opt/homebrew/opt/openssl/include \
    -L /opt/homebrew/opt/openssl/lib -lssl -lcrypto

COMMAND TO COMPILE RUNTIME_SERVER.C:
gcc runtime_server.c \
    -o runtime_server \
    -I /opt/homebrew/opt/openssl/include \
    -L /opt/homebrew/opt/openssl/lib -lssl -lcrypto

COMMAND TO COMPILE DAWN_CLIENT.C:
gcc dawn_client.c \
    -o dawn_client \
    -I /opt/homebrew/opt/openssl/include \
    -L /opt/homebrew/opt/openssl/lib -lssl -lcrypto