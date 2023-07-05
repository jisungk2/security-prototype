#!/bin/sh

gcc security.c \
    -o security \
    -I /opt/homebrew/opt/openssl/include \
    -L /opt/homebrew/opt/openssl/lib -lssl -lcrypto
