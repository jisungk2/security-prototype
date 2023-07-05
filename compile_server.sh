#!/bin/sh

gcc runtime_server.c \
    -o runtime_server \
    -I /opt/homebrew/opt/openssl/include \
    -L /opt/homebrew/opt/openssl/lib -lssl -lcrypto
