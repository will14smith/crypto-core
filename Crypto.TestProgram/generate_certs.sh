#!/bin/bash

SUBJ=//I=/C=GB/ST=London/L=London/O=localhost

rm -R localhost_ca localhost_ca_ec

mkdir -p localhost_ca/certs localhost_ca_ec/certs

openssl genrsa -out localhost_ca/key 2048
openssl req -new -x509 -key localhost_ca/key -out localhost_ca/cert -subj $SUBJ/CN=ca

touch localhost_ca/database localhost_ca_ec/database
echo 1000 > localhost_ca/serial
echo 1000 > localhost_ca_ec/serial
echo '[ca]
default_ca = CA_default

[CA_default]
dir = ./localhost_ca
database = $dir/database
new_certs_dir = $dir/certs
serial = $dir/serial
default_md = sha256
policy = policy_match
email_in_dn = no
default_days = 365

[policy_match]
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[v3_intermediate_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
' > localhost_ca/config

echo '[ca]
default_ca = CA_default

[CA_default]
dir = ./localhost_ca_ec
database = $dir/database
new_certs_dir = $dir/certs
serial = $dir/serial
default_md = sha256
policy = policy_match
email_in_dn = no
default_days = 365

[policy_match]
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[req]
distinguished_name = req_distinguished_name

[req_distinguished_name]
' > localhost_ca_ec/config

openssl ecparam -name prime256v1 -genkey -noout -out localhost_ca_ec/key
openssl req -config localhost_ca_ec/config -new -sha256 -key localhost_ca_ec/key -out localhost_ca_ec/csr -subj $SUBJ/CN=ca-ec
openssl ca -batch -config localhost_ca/config -extensions v3_intermediate_ca -cert localhost_ca/cert -keyfile localhost_ca/key -in localhost_ca_ec/csr -notext -out localhost_ca_ec/cert

cat localhost_ca/cert localhost_ca_ec/cert > localhost_ca.cert

openssl ecparam -name prime256v1 -out prime256v1.pem
openssl genpkey -paramfile prime256v1.pem -out localhost_ec.key
openssl req -new -key localhost_ec.key -out localhost_ec.csr -subj $SUBJ/CN=localhost
openssl x509 -req -in localhost_ec.csr -CA localhost_ca_ec/cert -CAkey localhost_ca_ec/key -CAcreateserial -out localhost_ec.cert
rm prime256v1.pem localhost_ec.csr

openssl genpkey -algorithm RSA -out localhost_rsa.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key localhost_rsa.key -out localhost_rsa.csr -subj $SUBJ/CN=localhost
openssl x509 -req -in localhost_rsa.csr -CA localhost_ca/cert -CAkey localhost_ca/key -CAcreateserial -out localhost_rsa.cert
rm localhost_rsa.csr