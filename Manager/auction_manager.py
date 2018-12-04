from Auction import auction
from flask import request, Flask
import requests
import json
import ssl
from OpenSSL import crypto
from os import listdir
from os.path import isfile, join
from PyKCS11 import ckbytelist, PyKCS11Error
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from binascii import a2b_base64
import pem
import random

#PEM_pass = getpass('PEM Passphrase: ')
PEM_pass = '12345'

with open('addresses.json', 'r') as myfile:
    addresses = json.load(myfile)

auction_manager_add = addresses['manager']
auction_repository_add = addresses['repository']

with open('addresses.json') as json_file:
    data = json.load(json_file)
    auction_repository_ip = data["repository"]
app = Flask(__name__)

def get_public_key(cert):
    # Convert from PEM to DER
    
    lines = cert.as_text().replace(" ",'').split()
    der = a2b_base64(''.join(lines[1:-1]))

    # Extract subjectPublicKeyInfo field from X.509 certificate (see RFC3280)
    cert = DerSequence()
    cert.decode(der)
    tbsCertificate = DerSequence()
    tbsCertificate.decode(cert[0])
    subjectPublicKeyInfo = tbsCertificate[6]

    # Initialize RSA key
    return RSA.importKey(subjectPublicKeyInfo)

certs = pem.parse_file('SSL/certificates.pem')
repository_public_key = get_public_key(certs[0])
privKey = crypto.load_privatekey(crypto.FILETYPE_PEM, open("SSL/key.pem", 'r').read(), passphrase=PEM_pass.encode('utf-8'))
input(privKey)

def encrypt(data):
    return repository_public_key.encrypt(data, random.getrandbits(128))

def decrypt(data):
    return None #TODO  #privKey.decrypt(data)


@app.route('/createAuction', methods=['POST'])
def createAuction():
    name = request.form['name']
    timeLimit = request.form['timeLimit']
    description = request.form['description']
    auctionType = request.form['auctionType']
    creator = json.loads(request.form['creator'])
    bid_validations = request.form.get('bid_validations') 

    if not confirmSignature(creator["Certificate"], creator["Signature"]):
        return "Auction not created: User not authenticated."

    try:
        f = open("serialNumber", "r+") 
        serialNumber = int(f.readline())
        f.seek(0,0)
    except FileNotFoundError:
        f = open("serialNumber", "w")
        serialNumber = 0

    f.write(str(serialNumber + 1))
    f.close()

    r = s.post(auction_repository_ip + "/create_auction", data={'serialNumber': serialNumber, 'name': name, 'timeLimit': timeLimit, 'description': description, 'auctionType': auctionType, 'creator' : creator['BI']})
    return "Auction " + str(serialNumber) + " created\n"

@app.route('/closeAuction', methods=['POST'])
def closeAuction():
    creator = json.loads(request.form['user'])
    auction = request.form['serial_number']

    if not confirmSignature(creator["Certificate"], creator["Signature"]):
        return "Auction not created: User not authenticated."

    r = s.post(auction_repository_add + '/close_auction', data = {
        'serial_number' : auction,
        'user' : creator['BI']
    })

    return r.text

def verifyCert(cert):
    files = ["CCCerts/" + f for f in listdir('CCCerts') if isfile(join('CCCerts', f))]
    trusted_certs = [ crypto.load_certificate(crypto.FILETYPE_PEM, open(x, 'r').read()) for x in files ]
    store = crypto.X509Store()
    for trusted_cert in trusted_certs:
        store.add_cert(trusted_cert)

    store_ctx = crypto.X509StoreContext(store, cert)
    try:
        result = store_ctx.verify_certificate()
    except crypto.X509StoreContextError:
        return False
    return True

def confirmSignature(cert, signature):
    try:
        certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, bytes(cert))
    except crypto.Error:
        print("Invalid certificate")
        return False


    if not verifyCert(certificate):
        print("Certificate is not valid.")
        return False

    try:
        signature = bytes(ckbytelist(bytes(json.loads(signature))))
    except PyKCS11Error:
        print("Signature is not valid.")
        return False

    BI = [x[1] for x in certificate.get_subject().get_components() if "serialNumber" in str(x[0])][0]
    try:
        crypto.verify(certificate, signature, BI, 'RSA-SHA1')
    except crypto.Error:
        print("Signature is not valid")
        return False

    return True
        
if __name__ == "__main__":
    #s = requests.Session()
    s = requests
    #s.verify = "SSL/certificates.pem"
    #context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
    #Should prompt OpenSSL to ask for password
    #context.load_cert_chain('SSL/certificate.pem', keyfile='SSL/key.pem', password = PEM_pass)
    
    
    app.run(host="127.0.0.1", port="5000", debug=True)#, ssl_context=context)
