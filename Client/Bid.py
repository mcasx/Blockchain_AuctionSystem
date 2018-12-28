import hashlib
import base64

def base64_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data)

def base64_decode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.b64decode(data)

class Bid(object):
    def __init__(self, user, value):
        self.user = user
        self.value = value
        #Note that this hash should never be altered after the Bid has been created, for mining use the function hash()
        self.originalHash = self.hash().hexdigest()

    def hash(self):
        m = hashlib.sha256()
        if(isinstance(self.user, str)):
            m.update(self.user.encode('utf-8'))
        else:
            m.update(self.user)
        
        if(isinstance(self.value, str)):
            m.update(self.value.encode('utf-8'))
        elif (isinstance(self.value, float)):
            m.update(str(self.value).encode('utf-8'))
        else:
            m.update(self.value)
        
        return m

    def __dict__(self):
        return {'user' : base64_encode(self.user).decode('utf-8'), 'value' : base64_encode(self.value).decode('utf-8'), 'originalHash' : self.originalHash}
