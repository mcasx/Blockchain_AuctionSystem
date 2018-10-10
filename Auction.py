from hashlib import sha256
from Bid import Bid
from datetime import datetime, timedelta
import threading

class Auction:
    
    def __init__(self, name, serial_number, time_limit, description, auction_type, creator, rules):
        self.name = name
        self.serial_number = serial_number
        self.time_limit = time_limit
        self.description = description
        self.auction_type = auction_type
        self.creator = creator
        self.bids = []
        self.rules = rules
        self.state = "Open"
        now = datetime.now()
        if now > time_limit:
            self.close()
        else:
            delay = (time_limit - now).total_seconds()
            threading.Timer(delay, self.close).start()

        
    def add_bid(self, user, value):
        if self.rules(self, user, value):
            self.bids.append(Bid(user, value, None) if not len(self.bids) else Bid(user, value, sha256(self.bids[-1])))
            return True
        else:
            return False

    def close(self):
        self.state = "Closed"