#import auction
from flask import Flask

app = Flask(__name__)
auctions = []

@app.route("/")
def hello():
    return "Hey"


if __name__ == "__main__":
    app.run()
