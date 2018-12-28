import hashlib
from Bid import Bid
import json
import random

class Block(object):
    def __init__(self, bid = None, prev_signature = None, nonce = 0):
        self.bid = bid
        self.prev_signature = prev_signature
        self.nonce = int(random.getrandbits(128)) if bid is None else nonce

    def hash(self):
        
        m = hashlib.sha256()
        if not self.bid is None:
            m.update(self.bid.originalHash)
            m.update(str(self.prev_signature).encode('utf-8'))

        m.update(str(self.nonce).encode('utf-8'))
        return m

    def validHash(self, challenge):
        h = self.hash().hexdigest()
        for i in range(0, challenge):
            if h[i] != '0':
                return False            
        return True

    def mine(self, challenge):
        while not self.validHash(challenge):
            self.nonce += 1

    def verifyNonce(self, nonce, chalenge):
        self.nonce = nonce
        if self.validHash(chalenge):
            return True
        else:
            self.nonce = 0
        return False

    def get_json_block(self):
        return json.dumps(Block().__dict__) if self.bid is None else json.dumps(Block(self.bid.__dict__, self.prev_signature, self.nonce).__dict__)

def get_block_from_dict(block):
    return Block() if block['bid'] is None\
        else Block(Bid(block['bid']['user'], float(block['bid']['value']), block['bid']['timeStamp']), block['prev_signature'])

    
