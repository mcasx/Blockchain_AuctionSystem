import hashlib

class Block(object):
    def __init__(self, bid, prev_signature):
        self.bid = bid
        self.prev_signature = prev_signature
        self.nonce = 0

    def hash(self):
        m = self.bid.hash()
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
