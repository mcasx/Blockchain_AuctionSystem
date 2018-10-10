from Auction import Auction
from flask import Flask,request
import pickle
import datetime

app = Flask(__name__)
auctions = []

@app.route("/")
def hello():
    return "Hey"

@app.route("/create_auction", methods=['GET', 'POST'])
def create_auction():
    auction = pickle.loads(request.form['auction'])
    auctions.append(auction)
    return "Auction Created"

@app.route("/bid", methods=['POST'])
def bid():
    serial_number = request.form['serial_number']
    print(serial_number)
    auction = get_auction(serial_number)
    if auction == None: return "Auction does not exist"
    if auction.state == "Closed": return "Bid refused"
    user = request.form['user']
    value = request.form['value']
    
    return "Bid added" if auction.add_bid(user, value) else "Bid refused"

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
        if a.serial_number == serial_number: return a.serial_number
    return None


if __name__ == "__main__":
    app.run()

