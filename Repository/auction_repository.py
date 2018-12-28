from Auction import auction
from flask import Flask,request
import pickle
from datetime import datetime, timedelta
from Block import Block, get_block_from_dict
import threading
import uuid
import json
import hashlib
import ssl
import requests
import base64
import codecs
from OpenSSL import crypto
from getpass import getpass
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from binascii import a2b_base64
import pem
import random
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import AES
from Crypto.Hash.HMAC import HMAC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random


app = Flask(__name__)
auctions = []

#PEM_pass = getpass('PEM Passphrase: ')
PEM_pass = '12345'

with open('../addresses.json', 'r') as myfile:
    addresses = json.load(myfile)

auction_manager_add = addresses['manager']
auction_repository_add = addresses['repository']

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
manager_public_key = get_public_key(certs[0])
with open("SSL/key.pem","rb") as mf:
    private_key = RSA.importKey(mf.read(), passphrase=PEM_pass)


def encrypt_man(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(manager_public_key.encrypt(data, random.getrandbits(128))[0])

def encrypt_sym(data, key):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return base64.b64encode(iv + cipher.encrypt(data))

def decrypt(data):
    return private_key.decrypt(base64.b64decode(data))


def createReceipt(block):
    return private_key.sign(block.bid.originalHash.encode(), random.getrandbits(128))[0]
    

def decrypt_sym(enc, key):
    enc = base64.b64decode(enc)
    iv = enc[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.decrypt(enc[AES.block_size:]).decode('utf-8')

recent_keys = []

def clear_old_keys():
    datetime.now()
    global recent_keys
    recent_keys = [x for x in recent_keys if (datetime.now() - x[0]).total_seconds() < 10]

def check_for_replay_attack(key):
    clear_old_keys()
    if key in [x[1] for x in recent_keys]:
        return True
    else:
        recent_keys.append((datetime.now(), key))
        return False

def base64_encode(data):
    return base64.b64encode(data)

def base64_decode(data):
    return base64.b64decode(data)

@app.route("/")
def hello():
    return "Hey "

@app.route("/create_auction", methods=['POST'])
def create_auction():

    key = decrypt(request.form['key'])
    
    data = json.loads(decrypt_sym(request.form['symdata'], key))

    received_mac = request.form['signature']
    mac = HMAC(key, msg=request.form['symdata'], digestmod=SHA256) 

    if(received_mac != mac.hexdigest()):
        return 'Data Integrity Compromised!'

    name = data['name']
    time_limit = datetime.strptime(data['timeLimit'], '%b %d %Y %I:%M%p')
    description = data['description']
    auction_type = data['auctionType']
    creator = data['creator']
    bid_validations = (data['bid_validations'] if 'bid_validdations' in data else None)
    serial_number = data['serialNumber']
    new_auction = auction(name, serial_number, time_limit, description, auction_type, creator, bid_validations)
    
    now = datetime.now()

    if now > new_auction.time_limit:
        _close_auction(new_auction)
    else:
        delay = (new_auction.time_limit - now).total_seconds()
        threading.Timer(delay, _close_auction, [new_auction]).start()

    auctions.append(new_auction)
    print(creator)

    return "Auction Created"

@app.route("/create_test_auction")
def create_test_auction():
    auctions.append(
        auction(
            str(uuid.uuid4()), 
            str(uuid.uuid4()),
            datetime.now(),
            str(uuid.uuid4()),
            0,
            str(uuid.uuid4()),
            None
        )
    )
    return json.dumps(auctions[-1].__dict__, indent=4, default=str)
    

@app.route("/place_bid", methods=['POST'])
def place_bid():

    key = decrypt(request.form['key'])
    check_for_replay_attack(key)

    data = json.loads(decrypt_sym(request.form['symdata'], key))

    received_mac = request.form['signature']
    mac = HMAC(key, msg=request.form['symdata'], digestmod=SHA256) 

    if(received_mac != mac.hexdigest()):
        return 'Data Integrity Compromised!'

    serial_number = data['serial_number']
    auction = get_auction(serial_number)

    if auction == None: return json.dumps("Auction does not exist")
    if auction.state == "Closed": return json.dumps("Bid refused")

    block = get_block_from_dict(json.loads(data['block']))


    nonce = data['nonce']

    if not block.verifyNonce(nonce, auction.chalenge):
        return json.dumps("Bid refused")

    r = s.post(auction_manager_add + '/bid_authenticate', data = {
        'encrypted_user_data' : request.form['encrypted_user_data'],
        'user_mac' : request.form['user_mac'],
        'user_key' : request.form['user_key'],
        'auction': auction.serial_number,
        'value': block.bid.value
    })

    if r.text == 'False':
        return json.dumps("User authentication Failed")

    if r.text == 'Invalid':
        return json.dumps("Invalid value")

    bid_data = json.loads(r.text)
    block.bid.user = base64_decode(bid_data['user'].encode())
    block.bid.value = base64_decode(bid_data['value'].encode())
    if auction.auction_type == "English Auction" and auction.get_last_block().bid:
        if (auction.get_last_block().bid.value >= block.bid.value):
            return json.dumps("Bid not added: Value must be higher than highest bid")

    auction.add_block(block)
    receipt = createReceipt(block)
    return json.dumps(("Bid added", receipt))

    
@app.route('/get_last_auction_bid', methods=['GET'])
def get_last_auction_bid():
    serial_number = int(request.args.get('serial_number'))
    auction = get_auction(serial_number)
    if not auction:
        return 'Auction does not exist'
    return json.dumps(auction.get_last_bid())

@app.route('/get_last_auction_block', methods=['GET'])
def get_last_auction_block():
    serial_number = int(request.args.get('serial_number'))
    auction = get_auction(serial_number)
    if not auction:
        return 'Auction does not exist'
    
    value = (auction.get_last_block().bid.value if not auction.get_last_block().bid is None else 0)
    if isinstance(value, bytes):
        value = value.decode()
    return json.dumps({'auction_type':auction.auction_type, 'hash':auction.get_last_block().hash().hexdigest(), 'value': value}) 

@app.route('/get_open_user_auctions', methods=['GET'])
def get_open_user_auctions():
    return str(json.dumps([x.__dict__ for x in [y for y in auctions if (y.state == 'Open' and y.creator == request.args.get('user'))]], indent=4, default=str))

@app.route('/get_open_auctions', methods=['GET'])
def get_open_auctions():
    return str(json.dumps([x.__dict__ for x in [y for y in auctions if y.state == 'Open']], indent=4, default=str))

@app.route('/get_blocks', methods=['GET'])
def get_blocks():
    return json.dumps([x.get_json_block() for x in get_auction(int(request.args.get('serial_number'))).blocks])

def _close_auction(auction):
    
    r = s.post(auction_manager_add + '/get_decrypt_key', data = {
        'auction' : auction.serial_number,
        'signature' : json.dumps(private_key.sign(auction.serial_number, random.getrandbits(128)))
    })
    
    key = decrypt(r.content)

    for block in auction.blocks[1:]:
        print(block.bid.user)
        block.bid.user = decrypt_sym(block.bid.user, key)
        print(block.bid.user)
        if auction.auction_type == "Blind Auction":
            block.bid.value = decrypt_sym(block.bid.value, key)
    
    auction.close()
    return True

@app.route("/close_auction", methods=['POST'])
def close_auction():
    serial_number = int(request.form['serial_number'])
    user = request.form['user']
    auction = get_auction(serial_number)
    if auction.creator != user: return "Wrong user!"
    if auction == None: return "Auction does not exist"
    if auction.state == "Closed": return "Auction already closed"
    result = _close_auction(auction)
    if result == True:
        return "Auction closed successfully"
    return "Error closing the auction"


def get_auction(serial_number):
    for a in auctions:
        if a.serial_number == serial_number: return a
    return None


@app.route("/get_auctions", methods=['GET'])
def get_auctions():
    return str(json.dumps([x.__dict__ for x in auctions], indent=4, default=str))

if __name__ == "__main__":
    '''
    Removed SSL
    s = requests.Session()
    s.verify = "SSL/certificates.pem"
    
    context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
    #Should prompt OpenSSL to ask for password
    context.load_cert_chain('SSL/certificate.pem', keyfile='SSL/key.pem', password = PEM_pass)
    '''
    s = requests
    app.run(host='127.0.0.1', port=3000, debug=True)#, ssl_context=context)
