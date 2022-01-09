#!/bin/bash

# Generate directory structure
mkdir -p ./certs/{server,client,ca}

#=======================#
# CERTIFICATE AUTHORITY #
#=======================#
# Generate authority key and certificate
openssl req -new -x509 -days 365 -keyout ./certs/ca/ca.key -out ./certs/ca/ca.crt

#========#
# SERVER #
#========#
# Generate key
openssl genrsa -out ./certs/server/server.key 4096
# Generate certificate signing request
openssl req -new -key ./certs/server/server.key -out ./certs/server/server.csr
# Sign certificate with self-signed CA
openssl x509 -req -days 365 -in ./certs/server/server.csr -CA ./certs/ca/ca.crt -CAkey ./certs/ca/ca.key -CAcreateserial -out ./certs/server/server.crt
# Verify certificate
openssl verify -CAfile ./certs/ca/ca.crt ./certs/server/server.crt

#========#
# CLIENT #
#========#
# Generate key
openssl genrsa -out ./certs/client/client.key 4096
# Generate certificate signing request
openssl req -new -key ./certs/client/client.key -out ./certs/client/client.csr
# Sign certificate with self-signed CA
openssl x509 -req -days 365 -in ./certs/client/client.csr -CA ./certs/ca/ca.crt -CAkey ./certs/ca/ca.key -CAcreateserial -out ./certs/client/client.crt
# Verify certificate
openssl verify -CAfile ./certs/ca/ca.crt ./certs/client/client.crt
# Convert cert & key into pfx certificate
openssl pkcs12 -inkey ./certs/client/client.key -in ./certs/client/client.crt -export -out ./certs/client/client.pfx

exit 0