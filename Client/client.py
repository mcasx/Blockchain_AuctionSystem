from consolemenu import *
from consolemenu.items import *
from datetime import datetime
from requests.exceptions import ConnectionError
import requests
import os
import json 
from random import randint

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def is_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False

def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False

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
        while True:
            try:
                time_limit = input('Time limit for the auction (e.g. Jun 1 2005 1:33PM) --> ')
                datetime.strptime(time_limit, '%b %d %Y %I:%M%p')
                break
            except ValueError:
                input("\nTime limit in the wrong format!\n\n Press enter to continue ")
                clear()
        clear()
        auction_type = input("Auction type:\n   · 1 - English Auction\n   · 2 - Blind Auction\n     --> ")
        auction_type = "English Auction" if auction_type == "1" else "Blind Auction"
        clear()
        creator = get_user()

        r = requests.post(auction_manager_add + "/createAuction", data={'name': name_of_auction, 'description': description, 'timeLimit': time_limit, 'auctionType': auction_type, 'creator' : creator})
        return r.text
    except ConnectionError:
        clear()
        print(bcolors.FAIL + 'Could not connect to Auction Manager\n\n' + bcolors.ENDC)
        input('Press enter to continue')

def create_test_auction():
    name_of_auction = "test name " + str(randint(1,100))
    clear()
    description = 'test description ' + str(randint(1,100))
    clear()
    time_limit = 'Jun 1 2020 1:33PM'
    clear()
    auction_type = "English Auction"
    clear()
    creator = get_user()
    r = requests.post(auction_manager_add + "/createAuction", data={
        'name': name_of_auction, 
        'description': description, 
        'timeLimit': time_limit, 
        'auctionType': auction_type, 
        'creator' : creator
    })
    input(r.text)
    return 
    
def close_auction():
    params = {'user':get_user()}
    r = requests.get(auction_repository_add + "/get_open_user_auctions", params=params) 
    auctions = json.loads(r.text)
    
    if not auctions:
        input('User has no open auctions\n\n\nPress enter to continue')
        return
    i = 1
    for auction in auctions:
        print(str(i) + ') ' + auction['serial_number'] + ' - ' + auction['name'])

    selection = input('\n' + 'Select auction to be closed (enter q to exit): ')
    while(not is_int(selection) or (int(selection) < 0 or int(selection)> len(auctions))):
        if(selection and selection[0] == 'q'): return
        clear()
        input('Invalid Selection\n\nPress Enter to continue ')
        clear()
        for auction in auctions:
            print(str(i) + ') ' + auction['serial_number'] + ' - ' + auction['name'])
        selection = input('\n' + 'Select auction to be closed (enter q to exit): ')
    
    r = requests.post(auction_repository_add + '/close_auction', data = {
        'serial_number' : auctions[int(selection)-1]['serial_number']
    })
    input('\n' + r.text + '\n\nPress Enter to continue')
    return 
    #todo

def place_bid():
    params = {'user':get_user()}
    r = requests.get(auction_repository_add + "/get_open_user_auctions", params=params) 
    auctions = json.loads(r.text)
    
    if not auctions:
        input('There are no open auctions\n\nPress enter to continue')
        return
    
    i = 1

    for auction in auctions:
        print('\n' + (str(i) if i > 10 else ('0' + str(i))) + ') Serial Number: ' + auction['serial_number'] + '\n    Name         : ' + auction['name'])
        i += 1
    selection = input('\n' + 'Select auction to bid (enter q to exit): ')

    while(not is_int(selection) or (int(selection) < 0 or int(selection)> len(auctions))):
        if(selection and selection[0] == 'q'): return
        clear()
        input('Invalid Selection\n\nPress Enter to continue ')
        clear()
        for auction in auctions:
            print(str(i) if i > 10 else ('0' + str(i)) + ') Serial Number: ' + auction['serial_number'] + '\n    Name: ' + auction['name'])
        selection = input('\n' + 'Select auction to bid (enter q to exit): ')

    auction = auctions[int(selection)-1]
    clear()

    value = input('\nInsert value to bid: ')
    
    while(not is_number(value)):
        input('\n Invalid value!\n\nPress enter to continue')
        value = input('\nInsert value to bid: ')

    
    r = requests.post(auction_repository_add + "/place_bid", data = {
        'user' : get_user(),
        'serial_number' : auction['serial_number'],
        'value': value
    })
    input(r.text + '\n\nPress enter to continue')
    return
    #todo

def get_auctions():
    
    r = requests.get(auction_repository_add + "/get_auctions")
    auctions = json.loads(r.text)
    if auctions == []: 
        input('No auctions in the repository\n\nPress Enter to continue')
        return
    i = 0
    for auction in auctions:
        clear()
        for key in auction:
            print(key + ': ' + str(auction[key]))
        i+=1
        cnt_str = input('\n\n\nBid ' + str(i) + '/' + str(len(auctions)) + '\n\nContinue ([y]/n): ')
        if cnt_str and cnt_str == 'n': return
    

if __name__ == "__main__":
    s = requests.Session()
    s.verify = "ssl/certificates.pem"
    
    menu = ConsoleMenu("Auction Client")
    clear = lambda: os.system('clear')

    with open('addresses.json', 'r') as myfile:
        addresses = json.load(myfile)

    auction_manager_add = addresses['manager']
    auction_repository_add = addresses['repository']


    function_item = FunctionItem("Say Hello", hello)
    create_auction_item = FunctionItem("Create Auction", create_auction)
    create_test_auction_item = FunctionItem("Create Test Auction", create_test_auction)
    get_auctions_item = FunctionItem("Get Auctions", get_auctions)
    close_auction = FunctionItem("Close Auction", close_auction)
    bid_item = FunctionItem("Place Bid", place_bid)


    menu.append_item(function_item)
    menu.append_item(create_auction_item)
    menu.append_item(create_test_auction_item)
    menu.append_item(get_auctions_item)
    menu.append_item(close_auction)
    menu.append_item(bid_item)

    menu.show()