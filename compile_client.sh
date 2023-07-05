#!/bin/sh

gcc dawn_client.c \
    -o dawn_client \
    -I /opt/homebrew/opt/openssl/include \
    -L /opt/homebrew/opt/openssl/lib -lssl -lcrypto
