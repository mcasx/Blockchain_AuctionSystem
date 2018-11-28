import hashlib

class Block(object):
    def __init__(self, bid = None, prev_signature = None):
        self.bid = bid
        self.prev_signature = prev_signature
        self.nonce = 0

    def hash(self):
        
        if not self.bid is None:
            m = self.bid.hash()
            m.update(str(self.prev_signature).encode('utf-8'))
        else:
            m = m = hashlib.sha256()
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