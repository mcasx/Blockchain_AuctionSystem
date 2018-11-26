# Country Name: PT
# Province Name: Aveiro
# Locality Name: Aveiro
# Organization Name: UA
# Organizational Unit: DETI
# Common Name: 127.0.0.1
# Email address: manuelxarez@ua.pt
openssl req -newkey rsa:2048 -keyout key.pem -x509 -days 365 -out certificate.pem

#Create public key
openssl x509 -pubkey -in certificate.pem -out public.pem
