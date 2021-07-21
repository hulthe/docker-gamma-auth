#!/bin/env sh

# Generate certificates for use during development
openssl req -x509 -nodes -new -sha256 -days 1024 -newkey rsa:2048 -keyout RootCA.key -out RootCA.pem -subj "/C=US/CN=Registry Auth CA"
openssl x509 -outform pem -in RootCA.pem -out RootCA.crt