import hashlib

class Bid(object):
    def __init__(self, user, value):
        self.user = user
        self.value = value
        #Note: timestamp is defined by server when it is processed
        self.timeStamp = None

    def hash(self):
        m = hashlib.sha256()
        m.update(self.user.encode('utf-8'))
        m.update(str(self.value).encode('utf-8'))
        return m