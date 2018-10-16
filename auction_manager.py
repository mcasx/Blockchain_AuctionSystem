from Auction import auction
from flask import request, Flask
import requests
import json

with open('addresses.json') as json_file:
    data = json.load(json_file)
    auction_repository_ip = data["repository"]
app = Flask(__name__)
 
@app.route('/createAuction', methods=['POST'])
def createAuction():
    name = request.form['name']
    timeLimit = request.form['timeLimit']
    description = request.form['description']
    auctionType = request.form['auctionType']
    creator = request.form['creator']
    bid_validations = request.form.get('bid_validations') 

    try:
        f = open("serialNumber", "r+") 
        serialNumber = int(f.readline())
        f.seek(0,0)
    except FileNotFoundError:
        f = open("serialNumber", "w")
        serialNumber = 0

    print("hey")
    f.write(str(serialNumber + 1))
    f.close()

    r = requests.post(auction_repository_ip + "/create_auction", data={'serialNumber': serialNumber, 'name': name, 'timeLimit': timeLimit, 'description': description, 'auctionType': auctionType, 'creator' : creator})
    return "Auction " + str(serialNumber) + " created\n"

def closeAuction(user, serialNumber):
    return    

def validateBid(bid):
    return

if __name__ == "__main__":
    app.run()
