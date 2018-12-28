import hashlib

class Bid(object):
    def __init__(self, user, value):
        self.user = user
        self.value = value
        #Note that this hash should never be altered after the Bid has been created, for mining use the function hash()
        self.originalHash = self.hash().hexdigest()

    def hash(self):
        m = hashlib.sha256()
        m.update(self.user.encode('utf-8'))
        m.update(str(self.value).encode('utf-8'))
        return m

    def __dict__(self):
        return {'user' : str(self.user), 'value' : str(self.value), 'originalHash' : self.originalHash}
