class Auction:
    def __init__(self, name, serialNumber, timeLimit, description, auctionType, creator):
        self.name = name
        self.serialNumber = serialNumber
        self.timeLimit = timeLimit
        self.description = description
        self.auctionType = auctionType
        self.creator = creator
        self.bids = [] 
