from Bid import Bid
from Block import Block

class auction(object):
    def __init__(self, name, serial_number, time_limit, description, auction_type, creator, rules = None):
        self.name = name
        self.serial_number = serial_number
        self.time_limit = time_limit
        self.description = description
        self.auction_type = auction_type
        self.creator = creator
        self.blocks = [Block()]
        self.rules = rules
        self.state = "Open"
        self.chalenge = 1
    ''' 
    def add_bid(self, user, value, hash_value):
        
        if self.rules:
            if self.rules(self, user, value):
                if self.auction_type == 'English Auction' and value <= self.get_last_bid().value:
                    return False
                self.bids.append(Bid(user, value, None) if not self.bids else Bid(user, value, hash_value))
                return True
            else:
                return False
        else:
            self.bids.append(Bid(user, value, hash_value))
            return True
    
    def get_last_bid(self):
        return self.bids[-1] if self.bids else None
    '''

    def add_block(self, block):
        self.blocks.append(block)

    def get_last_block(self):
        return self.blocks[-1] if self.blocks else None

    def close(self):
        self.state = "Closed"