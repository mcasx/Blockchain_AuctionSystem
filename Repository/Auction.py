from Bid import Bid
from Block import Block
import time
from math import floor, log

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
        self.blockTimes = []


    def add_block(self, block):
        self.blocks.append(block)
        self.blockTime.append(time.time())
        self._def_challenge()

    def _def_challenge(self):
        now = time.time()
        requests = len([x for x in self.blockTimes if now - x < 60])
        challenge = floor(log(requests))
        if challenge > 1:
            self.chalenge = challenge
        else:
            self.chalenge = 1

    def get_last_block(self):
        return self.blocks[-1] if self.blocks else None

    def close(self):
        self.state = "Closed"
