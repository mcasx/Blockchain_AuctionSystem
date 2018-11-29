from Auction import auction
from flask import request, Flask
import requests
import json
import ssl

with open('addresses.json') as json_file:
    data = json.load(json_file)
    auction_repository_ip = data["repository"]
app = Flask(__name__)
 
@app.route('/createAuction', methods=['POST'])
def createAuction():
    name = request.form['name']
    timeLimit = request.form['timeLimit']
    description = request.form['description']
    auctionType = request.form['auctionType']
    creator = request.form['creator']
    bid_validations = request.form.get('bid_validations') 

    try:
        f = open("serialNumber", "r+") 
        serialNumber = int(f.readline())
        f.seek(0,0)
    except FileNotFoundError:
        f = open("serialNumber", "w")
        serialNumber = 0

    print("hey")
    f.write(str(serialNumber + 1))
    f.close()

    r = s.post(auction_repository_ip + "/create_auction", data={'serialNumber': serialNumber, 'name': name, 'timeLimit': timeLimit, 'description': description, 'auctionType': auctionType, 'creator' : creator})
    return "Auction " + str(serialNumber) + " created\n"

@app.route('/verify_user', methods = ['POST'])
def verify_user():
    user_data = json.loads(request.form['user_data'])
    return confirmSignature(user_data['BI'], user_data['Certificate'], user_data['Signature'])

def closeAuction(user, serialNumber):
    return    

def verifyCert(cert):
    files = ["CCCerts/" + f for f in listdir('CCCerts') if isfile(join('CCCerts', f))]
    trusted_certs = [ crypto.load_certificate(crypto.FILETYPE_PEM, open(x, 'r').read()) for x in files ]
    store = crypto.X509Store()
    for trusted_cert in trusted_certs:
        store.add_cert(trusted_cert)

    store_ctx = crypto.X509StoreContext(store, certificate)
    try:
        result = store_ctx.verify_certificate()
    except crypto.X509StoreContextError:
        return false
    return true

def confirmSignature(BI, cert, signature):
    certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
    if not verifyCert(certificate):
        print("Certificate is not valid.")
        return false

    try:
        crypto.verify(certificate, signature, BI, 'RSA-SHA1')
    except crypto.Error:
        print("Signature is not valid")
        return false

    return true
        



if __name__ == "__main__":
    s = requests.Session()
    s.verify = "SSL/certificates.pem"

    context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
    #Should prompt OpenSSL to ask for password
    context.load_cert_chain('SSL/certificate.pem', keyfile='SSL/key.pem')
    app.run(host="127.0.0.1", port="5000", debug=True, ssl_context=context)
