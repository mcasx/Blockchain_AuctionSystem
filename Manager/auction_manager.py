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
import base64
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash.HMAC import HMAC
from Crypto.Hash import SHA256
from datetime import datetime


#PEM_pass = getpass('PEM Passphrase: ')
PEM_pass = '12345'


recent_keys = []
auctions = {}


with open('addresses.json', 'r') as myfile:
    addresses = json.load(myfile)

auction_manager_add = addresses['manager']
auction_repository_add = addresses['repository']

with open('addresses.json') as json_file:
    data = json.load(json_file)
    auction_repository_ip = data["repository"]
app = Flask(__name__)

def encrypt_sym(data, key):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return base64.b64encode(iv + cipher.encrypt(data))


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
#privKey = crypto.load_privatekey(crypto.FILETYPE_PEM, open("SSL/key.pem", 'r').read(), passphrase=PEM_pass.encode('utf-8')).to_cryptography_key()

with open("SSL/key.pem","rb") as mf:
    private_key = RSA.importKey(mf.read(), passphrase=PEM_pass)

def encrypt_repo(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(repository_public_key.encrypt(data, random.getrandbits(128))[0])

def decrypt(data):
    return private_key.decrypt(base64.b64decode(data))

def base64_decode(data):
    return base64.b64decode(data)

def decrypt_sym(enc, key):
    enc = base64.b64decode(enc)
    iv = enc[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.decrypt(enc[AES.block_size:]).decode('utf-8')

recent_keys = []

def clear_old_keys():
    datetime.now()
    global recent_keys
    recent_keys = [x for x in recent_keys if (datetime.now() - x[0]).total_seconds() > 10]

def check_for_replay_attack(key):
    clear_old_keys()
    if key in [x[1] for x in recent_keys]:
        return True
    else:
        recent_keys.append((datetime.now(), key))
        return False


@app.route('/createAuction', methods=['POST'])
def createAuction():
    
    key = decrypt(request.form['key'])
    check_for_replay_attack(key)

    data = json.loads(decrypt_sym(request.form['symdata'], key))
    received_mac = request.form['signature']
    
    mac = HMAC(key, msg=request.form['symdata'], digestmod=SHA256) 
    if(received_mac != mac.hexdigest()):
        return 'Data Integrity Compromised!'

    name            = data['name']
    timeLimit       = data['timeLimit']
    description     = data['description']
    auctionType     = data['auctionType']
    creator         = json.loads(data['creator'])
    
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

    
    data = {
        'serialNumber': serialNumber,
        'name': name,
        'timeLimit': timeLimit,
        'description': description,
        'auctionType': auctionType, 
        'creator' : creator['BI']
    }

    auctions[serialNumber] = (auctionType, Random.get_random_bytes(32))

    key = Random.get_random_bytes(32)
    encrypted = encrypt_sym(json.dumps(data), key)
    mac = HMAC(key, msg=encrypted, digestmod=SHA256)

    r = s.post(auction_repository_ip + "/create_auction", data={
        'signature' : mac.hexdigest(),
        'symdata' : encrypted,
        'key' : encrypt_repo(key)
    })
    return "Auction " + str(serialNumber) + " created\n"


@app.route('/closeAuction', methods=['POST'])
def closeAuction():

    key = decrypt(request.form['key'])
    check_for_replay_attack(key)

    data = json.loads(decrypt_sym(request.form['symdata'], key))
    received_mac = request.form['signature']
    
    mac = HMAC(key, msg=request.form['symdata'], digestmod=SHA256) 
    if(received_mac != mac.hexdigest()):
        return 'Data Integrity Compromised!'

    creator = json.loads(data['user'])
    auction = data['serial_number']

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


@app.route('/verify_user', methods = ['POST'])
def verify_user():
    key = decrypt(request.form['user_key'])

    user_data = decrypt_sym(request.form['encrypted_user_data'], key)

    received_mac = request.form['user_mac']
    if not _verify_user(key, user_data, received_mac):
        return "False"

@app.route('/bid_authenticate', methods = ['POST'])
def bid_authenticate():
    key = decrypt(request.form['user_key'])

    user_data = json.loads(decrypt_sym(request.form['encrypted_user_data'], key))

    received_mac = request.form['user_mac']
    if not _verify_user(key, user_data, received_mac):
        return "False"
    
    auction = int(request.form['auction'])

    user = encrypt_sym(user_data['BI'], auctions[auction][1])
    if auctions[auction][0] == "Blind Auction":
        value = encrypt_sym(decrypt_sym(request.form['value'], key), auctions[auction][1])
    else:
        value = decrypt_sym(request.form['value'], key)
    
    return_value = {"user": user, "value": value}
    return json.dumps(return_value)
    

def _verify_user(key, user_data, received_mac):
    mac = HMAC(key, msg=request.form['encrypted_user_data'], digestmod=SHA256) 
    if(received_mac != mac.hexdigest()):
        return 'Data Integrity Compromised!'

    mac = HMAC(key, msg=user_data['encrypted_user_data'], digestmod=SHA256) 
    if(received_mac != mac.hexdigest()):
        return 'Data Integrity Compromised!'

    return confirmSignature(user_data['Certificate'], user_data['Signature']) 


if __name__ == "__main__":
    #s = requests.Session()
    s = requests
    #s.verify = "SSL/certificates.pem"
    #context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
    #Should prompt OpenSSL to ask for password
    #context.load_cert_chain('SSL/certificate.pem', keyfile='SSL/key.pem', password = PEM_pass)
    
    
    app.run(host="127.0.0.1", port="5000", debug=True)#, ssl_context=context)
