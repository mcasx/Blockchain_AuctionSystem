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
from PyKCS11 import *
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import getpass
import pem
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from binascii import a2b_base64
import random
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash.HMAC import HMAC
from Crypto.Hash import SHA256
import hashlib

urllib3.disable_warnings(urllib3.exceptions.SecurityWarning)
receipts = []

with open('user_info', 'rb') as mf:
    user_info = pickle.load(mf)

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
repository_public_key = get_public_key(certs[1])

def encrypt_repo(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(repository_public_key.encrypt(data, random.getrandbits(128))[0])

def encrypt_man(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(manager_public_key.encrypt(data, random.getrandbits(128))[0])

def encrypt_sym(data, key):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return base64.b64encode(iv + cipher.encrypt(data))

def base64_encode(data):
    return base64.b64encode(data)

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

def checkReceipt(receipt, hashBid):
    certs = pem.parse_file("SSL/certificates.pem")
    #Second cert is Repository which is the one we want here
    try:
        repository_public_key.verify(int(hashBid, 16), (receipt,))
    except crypto.Error:
        print("Receipt is invalid")
        return False
    return True
    
def getUserAuthInfo():
    if True:
        return user_info
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
            
            userInfo["Certificate"] = session.getAttributeValue(certHandle, [CKA_VALUE], allAsBinary=False)[0]
            cert = crypto.load_certificate(crypto.FILETYPE_ASN1,bytes(userInfo["Certificate"]))
            
            userInfo["BI"] = [x[1] for x in cert.get_subject().get_components() if "serialNumber" in str(x[0])][0].decode("utf-8")

            userInfo["Signature"] = str(session.sign(privKeyHandle, userInfo["BI"], Mechanism(CKM_SHA1_RSA_PKCS)))
            
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

        data = {'name': name_of_auction,
        'description': description,
        'timeLimit': time_limit,
        'auctionType': auction_type,
        'creator' : json.dumps(creator),
        'bid_validations' : None}

        key = Random.get_random_bytes(32)
        encrypted = encrypt_sym(json.dumps(data), key)
        mac = HMAC(key, msg=encrypted, digestmod=SHA256)

        r = s.post(auction_manager_add + "/createAuction", data={
            'signature' : mac.hexdigest(),
            'symdata' : encrypted,
            'key' : encrypt_man(key)})

        clear()

        if "User not authenticated" in r.text:
            print(bcolors.FAIL + r.text + bcolors.ENDC)
        else:
            print(bcolors.OKBLUE + r.text + bcolors.ENDC)
        input('Press enter to continue')

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
    creator = getUserAuthInfo()

    data = {'name': name_of_auction,
        'description': description,
        'timeLimit': time_limit,
        'auctionType': auction_type,
        'creator' : json.dumps(creator),
        'bid_validations' : None}

    key = Random.get_random_bytes(32)
    encrypted = encrypt_sym(json.dumps(data), key)
    mac = HMAC(key, msg=encrypted, digestmod=SHA256)

    r = s.post(auction_manager_add + "/createAuction", data={
            'signature' : mac.hexdigest(),
            'symdata' : encrypted,
            'key' : encrypt_man(key)
        }
    )
    input(r.text)
    return 

def close_auction():
    user = getUserAuthInfo()
    params = {'user':user['BI']}
    r = s.get(auction_repository_add + "/get_open_user_auctions", params=params)
    auctions = json.loads(r.text)
    
    if not auctions:
        input('User has no open auctions\n\n\nPress enter to continue')
        return
    i = 1
    
    for auction in auctions:
        print(str(i) + ') ' + str(auction['serial_number']) + ' - ' + auction['name'])
        i+=1

    selection = input('\n' + 'Select auction to be closed (enter q to exit): ')
    while(not is_int(selection) or (int(selection) < 0 or int(selection)> len(auctions))):
        if(selection and selection[0] == 'q'): return
        clear()
        input('Invalid Selection\n\nPress Enter to continue ')
        clear()
        i = 1
        for auction in auctions:
            print(str(i) + ') ' + str(auction['serial_number']) + ' - ' + auction['name'])
        i += 1
        selection = input('\n' + 'Select auction to be closed (enter q to exit): ')
    

    data = {
        'serial_number' : auctions[int(selection)-1]['serial_number'],
        'user' : json.dumps(user)
    }

    key = Random.get_random_bytes(32)
    encrypted = encrypt_sym(json.dumps(data), key)
    mac = HMAC(key, msg=encrypted, digestmod=SHA256)

    r = s.post(auction_manager_add + '/closeAuction', data = {
        'signature' : mac.hexdigest(),
        'symdata' : encrypted,
        'key' : encrypt_man(key)
    })

    input('\n' + r.text + '\n\nPress Enter to continue')
    return 
    


def place_bid():
    params = {'user':getUserAuthInfo()}
    r = s.get(auction_repository_add + "/get_open_auctions", params=params) 
    auctions = json.loads(r.text)
    
    if not auctions:
        input('There are no open auctions\n\nPress enter to continue')
        return
    
    i = 1

    for auction in auctions:
        print('\n' + (str(i) if i > 10 else ('0' + str(i))) + ') Serial Number: ' + str(auction['serial_number']) + '\n    Name         : ' + auction['name'])
        i += 1
    selection = input('\n' + 'Select auction to bid (enter q to exit): ')

    while(not is_int(selection) or (int(selection) < 0 or int(selection)> len(auctions))):
        if(selection and selection[0] == 'q'): return
        clear()
        input('Invalid Selection\n\nPress Enter to continue ')
        clear()
        i = 1
        for auction in auctions:
            print(str(i) if i > 10 else ('0' + str(i)) + ') Serial Number: ' + str(auction['serial_number']) + '\n    Name: ' + auction['name'])
            i += 1
        selection = input('\n' + 'Select auction to bid (enter q to exit): ')

    auction = auctions[int(selection)-1]['serial_number']

    clear()

    params = {'serial_number':auction} 
    r = s.get(auction_repository_add + "/get_last_auction_block", params=params) 
    
    block = json.loads(r.content)
    #input(block)

    value = input('\nInsert value to bid (last bid: '+ str(block['value']) +'): ') \
        if block['auction_type'] == 'English Auction' else input('\nInsert value to bid: ')
    
    while(not is_number(value) or ((float(block['value']) >= float(value)) if block['auction_type'] == 'English Auction' else (0 >= float(value)))):
        input('\n Invalid value!\n\nPress enter to continue')
        value = input('\nInsert value to bid: ')

    value = float(value)

    user_info = getUserAuthInfo()

    bid = Bid(user_info['BI'], value)

    user_key = Random.get_random_bytes(32)

    bid.value = encrypt_sym(str(bid.value), user_key)
    bid.user = encrypt_sym(bid.user, user_key)

    new_block = Block(bid, block['hash'])
    new_block.mine(int(auctions[int(selection)-1]['chalenge']))

    encrypted_user_info = encrypt_sym(json.dumps(user_info), user_key)
    user_mac = HMAC(user_key, msg=encrypted_user_info, digestmod=SHA256)

    data = {
        'serial_number' : auction,
        'block' : new_block.get_json_block(),
        'nonce' : new_block.nonce,
        
    }

    key = Random.get_random_bytes(32)
    encrypted = encrypt_sym(json.dumps(data), key)
    mac = HMAC(key, msg=encrypted, digestmod=SHA256)


    r = s.post(auction_repository_add + "/place_bid", data = {
        'symdata' : encrypted,
        'key' : encrypt_repo(key),
        'signature' : mac.hexdigest(),
        'encrypted_user_data' : encrypted_user_info,
        'user_mac' : user_mac,
        'user_key' : encrypt_man(user_key)
    })

    response = json.loads(r.text)

    if isinstance(response, list):
        receipt = response[1]
        if checkReceipt(receipt, new_block.bid.originalHash):
            receipts.append({'auction': auction, 'block': new_block, 'receipt':receipt})
        else:
            print("WARNING: INVALID RECEIPT")

    input(response)

    input(response[0] + '\n\nPress enter to continue')
    return
    #todo

def get_auctions():
    r = s.get(auction_repository_add + "/get_auctions")
    auctions = json.loads(r.text)
    if not auctions: 
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
    
def get_blocks_from_auction():
    r = s.get(auction_repository_add + "/get_auctions")
    auctions = json.loads(r.text)
    if not auctions: 
        input('No auctions in the repository\n\nPress Enter to continue')
        return

    i = 1
    for auction in auctions:
        print('\n' + (str(i) if i > 10 else ('0' + str(i))) + ') Serial Number: ' + str(auction['serial_number']) + '\n    Name         : ' + auction['name'])
        i += 1
    selection = input('\n' + 'Select auction (enter q to exit): ')

    while(not is_int(selection) or (int(selection) < 0 or int(selection)> len(auctions))):
        if(selection and selection[0] == 'q'): return
        clear()
        input('Invalid Selection\n\nPress Enter to continue ')
        clear()
        i = 1
        for auction in auctions:
            print(str(i) if i > 10 else ('0' + str(i)) + ') Serial Number: ' + str(auction['serial_number']) + '\n    Name: ' + auction['name'])
            i += 1
        selection = input('\n' + 'Select auction (enter q to exit): ')

    auction = auctions[int(selection)-1]['serial_number']

    params = {'serial_number': auction}
    r = s.get(auction_repository_add + "/get_blocks", params = params)
    
    for block in json.loads(r.content):
        print(block)
    input('\nPress enter to continue')

def view_receipts():
    if not receipts:
        print('There are no bids yet.')
    else:
        print(receipts)
    input('\nPress Enter to continue')

def validate_auction():
    r = s.get(auction_repository_add + "/get_auctions")
    auctions = json.loads(r.text)
    if not auctions: 
        input('No auctions in the repository\n\nPress Enter to continue')
        return

    i = 1
    for auction in auctions:
        print('\n' + (str(i) if i > 10 else ('0' + str(i))) + ') Serial Number: ' + str(auction['serial_number']) + '\n    Name         : ' + auction['name'])
        i += 1
    selection = input('\n' + 'Select auction (enter q to exit): ')

    while(not is_int(selection) or (int(selection) < 0 or int(selection)> len(auctions))):
        if(selection and selection[0] == 'q'): return
        clear()
        input('Invalid Selection\n\nPress Enter to continue ')
        clear()
        i = 1
        for auction in auctions:
            print(str(i) if i > 10 else ('0' + str(i)) + ') Serial Number: ' + str(auction['serial_number']) + '\n    Name: ' + auction['name'])
            i += 1
        selection = input('\n' + 'Select auction (enter q to exit): ')

    auction = auctions[int(selection)-1]['serial_number']

    params = {'serial_number': auction}
    r = s.get(auction_repository_add + "/get_blocks", params = params)
    
    print(json.loads(r.content))
    nonce_zero = json.loads(json.loads(r.text)[0])["nonce"]
    prev_hash = hashlib.sha256()
    prev_hash.update(str(nonce_zero).encode('utf-8'))
    for x in json.loads(r.text)[1:]:
        block = json.loads(x)
        if block["prev_signature"] != prev_hash.hexdigest():
            input("WARNING: Auction is invalid")
            clear()
            return
        prev_hash = hashlib.sha256()
        prev_hash.update(str(block["bid"]["originalHash"]).encode('utf-8'))
        prev_hash.update(str(block["prev_signature"]).encode('utf-8'))
        prev_hash.update(str(block["nonce"]).encode('utf-8'))

    input("Auction is valid!")
    clear()
    
    

if __name__ == "__main__":
    s = requests.Session()
    s.verify = "SSL/certificates.pem"

    menu = ConsoleMenu("Auction Client")
    clear = lambda: os.system('clear')

    with open('addresses.json', 'r') as myfile:
        addresses = json.load(myfile)

    auction_manager_add = addresses['manager']
    auction_repository_add = addresses['repository']


    create_auction_item = FunctionItem("Create Auction", create_auction)
    create_test_auction_item = FunctionItem("Create Test Auction", create_test_auction)
    get_auctions_item = FunctionItem("Get Auctions", get_auctions)
    close_auction = FunctionItem("Close Auction", close_auction)
    bid_item = FunctionItem("Place Bid", place_bid)
    receipts_item = FunctionItem("View Receipts", view_receipts)
    blocks_item = FunctionItem("Get Blocks of Auction", get_blocks_from_auction)
    vali_auction = FunctionItem("Validate Auction", validate_auction)

    menu.append_item(create_auction_item)
    menu.append_item(create_test_auction_item)
    menu.append_item(get_auctions_item)
    menu.append_item(close_auction)
    menu.append_item(bid_item)
    menu.append_item(receipts_item)
    menu.append_item(blocks_item)
    menu.append_item(vali_auction)

    menu.show()


