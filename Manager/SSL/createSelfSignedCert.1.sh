# Country Name: PT
# Province Name: Aveiro
# Locality Name: Aveiro
# Organization Name: UA
# Organizational Unit: DETI
# Common Name: 127.0.0.1
# Email address: manuelxarez@ua.pt
openssl genrsa -aes128 -out privkey.pem 2048

#Generate public key
openssl req -new -x509 -key privkey.pem 
