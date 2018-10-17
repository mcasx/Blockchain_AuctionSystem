from consolemenu import *
from consolemenu.items import *
from datetime import datetime
from requests.exceptions import ConnectionError
import requests
import os
import json

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



menu = ConsoleMenu("Auction Client")
clear = lambda: os.system('clear')


with open('addresses.json', 'r') as myfile:
    addresses = json.load(myfile)
auction_manager_add = addresses['manager']
auction_repository_add = addresses['repository']

def hello():
    input("hello")

def get_user():
    return "Hello my name is Jeff"

def create_auction():
    try:
        name_of_auction = input("Auction name --> ")
        clear()
        description = input("Description --> ")
        clear()
        time_limit = datetime.strptime(input('Time limit for the auction (e.g. Jun 1 2005 1:33PM) --> '), '%b %d %Y %I:%M%p')
        clear()
        auction_type = input("Auction type:\n   · 1 - English Auction\n   · 2 - Blind Auction\n     --> ")
        auction_type = "English Auction" if auction_type == "1" else "Blind Auction"
        clear()
        creator = get_user()

        r = requests.post(auction_manager_add + "/createAuction", data={'name': name_of_auction, 'description': description, 'time_limit': time_limit, 'auction_type': auction_type, 'creator' : creator})
        return r.text
    except ConnectionError:
        clear()
        print(bcolors.FAIL + 'Could not connect to Auction Manager\n\n' + bcolors.ENDC)
        input('Press enter to continue')


def close_auction():
    return ""
    #todo

def bid():
    return ""
    #todo

def get_auctions():
    
    r = requests.get(auction_repository_add + "/get_auctions")
    auctions = json.loads(r.text)
    i = 0
    for auction in auctions:
        clear()
        for key in auction:
            print(key + ': ' + str(auction[key]))
        i+=1
        input('\n\n\nBid ' + str(i) + '/' + str(len(auctions)) + '      Press Enter to continue')       
    

function_item = FunctionItem("Say Hello", hello)
create_auction_item = FunctionItem("Create Auction", create_auction)
get_auctions_item = FunctionItem("Get Auctions", get_auctions)
close_auction = FunctionItem("Close Auction", close_auction)
bid_item = FunctionItem("Place Bid", bid)

menu.append_item(function_item)
menu.append_item(create_auction_item)
menu.append_item(get_auctions_item)
menu.append_item(close_auction)
menu.append_item(bid_item)

menu.show()
