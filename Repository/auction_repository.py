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
import jsonpickle
from OpenSSL import crypto

app = Flask(__name__)
auctions = []
with open('../addresses.json', 'r') as myfile:
    addresses = json.load(myfile)

auction_manager_add = addresses['manager']
auction_repository_add = addresses['repository']

def createReceipt(block):
    privKey = crypto.load_privatekey(crypto.FILETYPE_PEM, open("SSL/key.pem", 'r').read())
    receipt = crypto.sign(privKey, block.prev_signature, 'RSA-SHA1')
    return receipt

@app.route("/")
def hello():
    return "Hey "

@app.route("/create_auction", methods=['POST'])
def create_auction():
    name = request.form['name']
    time_limit = datetime.strptime(request.form['timeLimit'], '%b %d %Y %I:%M%p')
    description = request.form['description']
    auction_type = request.form['auctionType']
    creator = request.form['creator']
    bid_validations = request.form.get('bid_validations') 
    serial_number = request.form['serialNumber']
    new_auction = auction(name, serial_number, time_limit, description, auction_type, creator, bid_validations)
    
    now = datetime.now()

    if now > new_auction.time_limit:
            new_auction.close()
    else:
        delay = (new_auction.time_limit - now).total_seconds()
        threading.Timer(delay, new_auction.close).start()
   
    auctions.append(new_auction)
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
    serial_number = request.form['serial_number']
    auction = get_auction(serial_number)
    if auction == None: return json.dumps("Auction does not exist")
    if auction.state == "Closed": return json.dumps("Bid refused")

    block = get_block_from_dict(json.loads(request.form['block']))
    
    nonce = request.form['nonce']

    r = s.post(auction_manager_add + '/verify_user', data = {
        'user_data' : request.form['user_data']
    })

    if r.text == 'False':
        return json.dumps("User authentication Failed")

    if block.verifyNonce(nonce, auction.chalenge):
        auction.add_block(block)
        receipt = createReceipt(block)
        return json.dumps(("Bid added", str(receipt)))
    return json.dumps("Bid refused")
    

@app.route('/get_last_auction_bid', methods=['GET'])
def get_last_auction_bid():
    serial_number = request.args.get('serial_number')
    auction = get_auction(serial_number)
    if not auction:
        return 'Auction does not exist'
    return json.dumps(auction.get_last_bid())

@app.route('/get_last_auction_block', methods=['GET'])
def get_last_auction_block():
    serial_number = request.args.get('serial_number')
    auction = get_auction(serial_number)
    if not auction:
        return 'Auction does not exist'
    return auction.get_last_block().get_json_block()

@app.route('/get_open_user_auctions', methods=['GET'])
def get_open_user_auctions():
    return str(json.dumps([x.__dict__ for x in [y for y in auctions if (y.state == 'Open' and y.creator == request.args.get('user'))]], indent=4, default=str))


@app.route("/close_auction", methods=['POST'])
def close_auction():
    serial_number = request.form['serial_number']
    auction = get_auction(serial_number)
    if auction == None: return "Auction does not exist"
    if auction.state == "Closed": return "Auction already closed"
    auction.state = "Closed"
    return "Auction closed"


def get_auction(serial_number):
    for a in auctions:
        if a.serial_number == serial_number: return a
    return None


@app.route("/get_auctions", methods=['GET'])
def get_auctions():
    return str(json.dumps([x.__dict__ for x in auctions], indent=4, default=str))

if __name__ == "__main__":
    s = requests.Session()
    s.verify = "SSL/certificates.pem"
    
    context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
    #Should prompt OpenSSL to ask for password
    context.load_cert_chain('SSL/certificate.pem', keyfile='SSL/key.pem')
    app.run(host='127.0.0.1', port=3000, debug=True, ssl_context=context)
