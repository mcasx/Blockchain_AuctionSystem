import json
import os
from datetime import datetime
from random import randint
import requests
from consolemenu import *
from consolemenu.items import *
import pickle
from requests.exceptions import ConnectionError
import urllib3
from Bid import Bid
from Block import Block, get_block_from_dict
import codecs


urllib3.disable_warnings(urllib3.exceptions.SecurityWarning)

from PyKCS11 import *
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import getpass

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
    return 'Jeff'

def getUserAuthInfo():
    userInfo = {"BI": None, "Certificate": None, "Signature": None}
    lib = 'opensc-pkcs11.so'
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(lib)
    slots = pkcs11.getSlotList()

    for slot in slots:
        if 'Auth PIN (CARTAO DE CIDADAO)' in pkcs11.getTokenInfo(slot).label:
            session = pkcs11.openSession(slot)
            PIN = getpass.getpass('CC PIN: ')
            session.login(PIN)

            certHandle = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE), (CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')])[0]

            privKeyHandle = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
            
            userInfo["Certificate"] = bytes(session.getAttributeValue(certHandle, [CKA_VALUE], allAsBinary=True)[0])
            cert = crypto.load_certificate(crypto.FILETYPE_ASN1,userInfo["Certificate"])
            
            userInfo["BI"] = [x[1] for x in cert.get_subject().get_components() if "serialNumber" in str(x[0])][0].decode("utf-8")

            userInfo["Signature"] = bytes(session.sign(privKeyHandle, userInfo["BI"], Mechanism(CKM_SHA1_RSA_PKCS)))
            
            session.closeSession

    return userInfo

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
        creator = getUserAuthInfo()

        r = s.post(auction_manager_add + "/createAuction", data={'name': name_of_auction, 'description': description, 'timeLimit': time_limit, 'auctionType': auction_type, 'creator' : creator})
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
    r = s.post(auction_manager_add + "/createAuction", data={
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
    r = s.get(auction_repository_add + "/get_open_user_auctions", params=params) 
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
    
    r = s.post(auction_repository_add + '/close_auction', data = {
        'serial_number' : auctions[int(selection)-1]['serial_number']
    })
    input('\n' + r.text + '\n\nPress Enter to continue')
    return 
    #todo

def place_bid():
    params = {'user':get_user()}
    r = s.get(auction_repository_add + "/get_open_user_auctions", params=params) 
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
        i = 1
        for auction in auctions:
            print(str(i) if i > 10 else ('0' + str(i)) + ') Serial Number: ' + auction['serial_number'] + '\n    Name: ' + auction['name'])
            i += 1
        selection = input('\n' + 'Select auction to bid (enter q to exit): ')

    auction = auctions[int(selection)-1]['serial_number']

    clear()

    params = {'serial_number':auction}

    r = s.get(auction_repository_add + "/get_last_auction_block", params=params) 
    
    input(r.text)
    block = get_block_from_dict(json.loads(r.content))

    value = input('\nInsert value to bid: ')
    
    while(not is_number(value)):
        input('\n Invalid value!\n\nPress enter to continue')
        value = input('\nInsert value to bid: ')

    value = float(value)

    user_info = getUserAuthInfo()

    bid = Bid(user_info['BI'], value)

    block.mine(2)

    new_block = Block(bid, block.hash().hexdigest())
    
    r = s.post(auction_repository_add + "/place_bid", data = {
        'serial_number' : auction,
        'user' : json.dumps(user_info),
        'block' : new_block.get_json_block(),
        'nonce' : block.nonce
    })
    input(r.text + '\n\nPress enter to continue')
    return
    #todo

def get_auctions():
    r = s.get(auction_repository_add + "/get_auctions")
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
    s.verify = "SSL/certificates.pem"
     
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


