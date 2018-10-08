import Auction
import json
import flask

app = flask.Flask(__name__)
serialNumber = 0

@app.route('/createAuction')
def createAuction(name, serialNumber, timeLimit, description, auctionType, creator, bid_validations = None):
    auction = Auction(name, self.serialNumber, timeLimit, description, auctionType, creator)
    jsonAuction = json.dumps(auction)

def closeAuction(user, serialNumber):
    return    

def validateBid(bid):
    return

if __name__ == "__main__":
    app.run()
