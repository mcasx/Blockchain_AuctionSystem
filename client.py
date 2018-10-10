from consolemenu import *
from consolemenu.items import *
from datetime import datetime
import requests
import os

menu = ConsoleMenu("Auction Client")
clear = lambda: os.system('clear')
auction_manager_ip = "0.0.0.0"

"""
# MenuItem is the base class for all items, it doesn't do anything when selected
menu_item = MenuItem("Menu Item")

# A FunctionItem runs a Python function when selected
function_item = FunctionItem("Call a Python function", input, ["Enter an input"])

# A CommandItem runs a console command
command_item = CommandItem("Run a console command",  "touch hello.txt")

# A SelectionMenu constructs a menu from a list of strings
selection_menu = SelectionMenu(["item1", "item2", "item3"])

# A SubmenuItem lets you add a menu (the selection_menu above, for example)
# as a submenu of another menu
submenu_item = SubmenuItem("Submenu item", selection_menu, menu)

# Once we're done creating them, we just add the items to the menu
menu.append_item(menu_item)
menu.append_item(function_item)
menu.append_item(command_item)
menu.append_item(submenu_item)
"""

def hello():
    input("hello")

def get_user():
    return "Hello my name is Jeff"

def create_auction():
    name_of_auction = input("Auction name --> ")
    clear()
    description = input("Description --> ")
    clear()
    time_limit = datetime.strptime(input('Time limit for the auction (e.g. Jun 1 2005 1:33PM)'), '%b %d %Y %I:%M%p')
    clear()
    auction_type = input("Auction type:\n   · 1 - English Auction\n   · 2 - Blind Auction\n     --> ")
    auction_type = "English Auction" if auction_type == "1" else "Blind Auction"
    clear()
    creator = get_user()

    #Substituir pelo ip do auction
    r = requests.post(auction_manager_ip + ":5000/create_auction", data={'name': name_of_auction, 'description': description, 'time_limit': time_limit, 'auction_type': auction_type, 'creator' : creator})

    


function_item = FunctionItem("Say Hello", hello)
create_auction_item = FunctionItem("Create Auction", create_auction)

menu.append_item(function_item)
menu.append_item(create_auction)
# Finally, we call show to show the menu and allow the user to interact
menu.show()
