from Auction import auction
from flask import Flask,request
import pickle
import datetime
from datetime import datetime, timedelta
import threading
import uuid
import json
import hashlib
import ssl

app = Flask(__name__)
auctions = []

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
    if auction == None: return "Auction does not exist"
    if auction.state == "Closed": return "Bid refused"
    user = request.form['user']
    value = request.form['value']
    if auction.bids:
        m = hashlib.sha256()
        m.update(auction.get_last_bid().__dict__)
        prev_hash = m.digest()
        return "Bid added" if auction.add_bid(user, value, prev_hash) else "Bid refused"
    else:
        return "Bid added" if auction.add_bid(user, value, None) else "Bid refused"

@app.route('/get_last_auction_bid', methods=['GET'])
def get_last_auction_bid():
    serial_number = request.args.get('serial_number')
    auction = get_auction(serial_number)
    if not auction:
        return 'Auction does not exist'
    return json.dumps(auction.get_last_bid())


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
    s = request.Session()
    s.verify = "SSL/certificates.pem"

    context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
    #Should prompt OpenSSL to ask for password
    context.load_cert_chain('SSL/certificate.pem', keyfile='SSL/key.pem')
    app.run(host='127.0.0.1', port=3000, debug=True, ssl_context=context)
