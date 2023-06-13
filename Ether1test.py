from PyQt5 import QtWidgets
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.uic import loadUi
from datetime import datetime
import sys
from eth_keys import keys
from eth_utils import decode_hex
from eth_account import Account
import secrets
import bs4
import requests
from web3 import Web3
from hexbytes import HexBytes
import qrcode
import pyqtgraph
from pysqlitecipher import sqlitewrapper               # This import is going to be used to create a encrypted sqlite database to replace the existing plaintext one
import sqlite3
class EtherOne(QDialog):
    def __init__(self):
        super(EtherOne, self).__init__()
        loadUi("Ether1.ui", self)
        self.Login.clicked.connect(self.gotologin)
        self.CreateWallet.clicked.connect(self.gotoCreateWallet)

    def gotologin(self):
        login = LoginScreen()
        widget.addWidget(login)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def gotoCreateWallet(self):
        create = CreateWalletScreen()
        widget.addWidget(create)
        widget.setCurrentIndex(widget.currentIndex()+1)

class CreateWalletScreen(QDialog):
    def __init__(self):
        super(CreateWalletScreen, self).__init__()
        loadUi("Ether1CreateWallet.ui", self)
        self.Password_field.setEchoMode(QtWidgets.QLineEdit.Password)
        self.ConfirmPassword.setEchoMode(QtWidgets.QLineEdit.Password)
        self.CreateWalletButton.clicked.connect(self.CreateWallet)

    def CreateWallet(self):
        user = self.Username_field.text()
        password = self.Password_field.text()
        confirmpassword = self.ConfirmPassword.text()
        privateKey = secrets.token_hex(32)
        privateKey1 = "0x" + privateKey
        priv_key_bytes = decode_hex(privateKey1)
        privateKey = keys.PrivateKey(priv_key_bytes)
        publicKey = privateKey.public_key
        acct = Account.from_key(privateKey)
        Address = acct.address
        columns = [
            [user, "TEXT"]
            [password, "TEXT"]
            [privateKey, "TEXT"]
            [publicKey, "TEXT"]
            [Address, "TEXT"]
        ]
        encryptedSQL = sqlitewrapper.SqliteCipher(dataBasePath="./Ether1.db" , checkSameThread=False , password="`eK_E^d2(#XD_Ma8")
        encryptedSQL.createTable("UserData", columns, makeSecure=True, commit=True)

        if len(user) == 0 or len(password)==0 or len(confirmpassword)==0:
            self.Error.setText("Fill Out This Form")

        elif password!=confirmpassword:
            self.Error.setText("Password Does Not Match")
        else:
            loginScreen = LoginScreen()
            widget.addWidget(loginScreen)
            widget.setCurrentIndex(widget.currentIndex()+1)

class LoginScreen(QDialog):
    def __init__(self):
        super(LoginScreen, self).__init__()
        loadUi("Ether1Login.ui", self)
        self.Password_field.setEchoMode(QtWidgets.QLineEdit.Password)
        self.Login.clicked.connect(self.LoginFunction)


    def LoginFunction(self):
        user = self.Username_field.text()
        password = self.Password_field.text()
        values = [user, password]
        conn = sqlite3.connect("Ether1data.db")
        cur = conn.cursor()
        query = 'SELECT username, password, privateKey, publicKey, walletAddress FROM UserData WHERE (username = (?) AND password = (?))'
        cur.execute(query, values)
        results = cur.fetchall()


        if len(user) == 0 or len(password)==0:
            self.Error.setText("Is Your Name on The List?")
        elif results == []:
            self.Error.setText("Your Name's Not On The List")
        elif results[0][0] == user and results[0][1] == password:
            homescreen = HomeScreen(results)
            sendscreen = SendETH(results)
            receivescreen = ReceiveETH(results)
            self.Error.setText("")
            name = str(results[0][0])
            homescreen.User.setText(" " + name.capitalize())
            homescreen.walletAddress.setText(results[0][4])
            widget.addWidget(homescreen)
            widget.setCurrentIndex(widget.currentIndex()+1)
            widget.addWidget(receivescreen)
            widget.addWidget(sendscreen)
        else:
            self.Error.setText("Nobody in Here Knows You")

class HomeScreen(QDialog):
    def __init__(self, results):
        super(HomeScreen, self).__init__()
        loadUi("Ether1Home.ui", self)
        pricelist = []
        timelist = []
        self.name = str(results[0][0])
        self.User.setText(" " + self.name.capitalize())
        self.walletAddress.setText(results[0][4])
        addr = results[0][4]
        self.EthereumWebRequest = requests.get('https://coinmarketcap.com/currencies/ethereum/')
        self.WebRequestSoup = bs4.BeautifulSoup(self.EthereumWebRequest.text, 'html.parser')
        self.Body = self.WebRequestSoup.find_all("body")[0]
        self.LiveEthereumPrice = self.Body.find('div', attrs = {'class' : 'priceValue'})
        self.price = (self.LiveEthereumPrice.text)
        self.price = self.price.lstrip("$")
        self.price = self.price.replace(",", "")
        self.Price.setText(self.price)
        self.time_of_day = datetime.now()
        self.time_of_day = str(self.time_of_day)
        self.time_of_day = self.time_of_day[11:14]
        self.time_of_day = self.time_of_day.replace(":", "")
        Address = requests.get('https://www.blockchain.com/eth/address/'+ addr)
        testNetAddress = Web3(Web3.HTTPProvider('https://ropsten.infura.io/v3/3c0b6b7eaed34d84894382a78aa4db18'))
        testBalance = testNetAddress.eth.getBalance(addr)
        testWallet = float(testBalance/1000000000000000000)
        self.Testnet.setText("TestNet Balance:" + str(testWallet))
        blocksoup = bs4.BeautifulSoup(Address.text, "html.parser")
        walletBalance = blocksoup.find_all("body")[0]
        balance = walletBalance.find('span', attrs = {'class' : 'sc-1ryi78w-0 cILyoi sc-16b9dsl-1 ZwupP u3ufsr-0 eQTRKC'})
        walletInfo = (balance.text)
        self.Mainnet.setText(walletInfo)


        for i in range(0,5):
            pricelist.append(float(self.price))
            timelist.append(int(self.time_of_day))
        #self.graphWidget.plot(pricelist, timelist)
        self.Send.clicked.connect(self.gotoSend)
        self.Receive.clicked.connect(self.gotoReceive)

    def gotoReceive(self):
        widget.setCurrentIndex(widget.currentIndex()+1)

    def gotoSend(self):
        widget.setCurrentIndex(widget.currentIndex()+2)

class SendETH(QDialog):
    def __init__(self, results):
       super(SendETH, self).__init__()
       loadUi("Ether1Send.ui", self)
       self.Sending.clicked.connect(self.SendEther)
       web3 = Web3(Web3.HTTPProvider('https://ropsten.infura.io/v3/3c0b6b7eaed34d84894382a78aa4db18'))
       account_1 = results[0][4]
       self.private_key1 = results[0][2]
       nonce = web3.eth.getTransactionCount(account_1)
       self.tx = {
        'nonce': nonce,
        'gas': 2000000,
        'gasPrice': web3.toWei('50', 'gwei')
        }
    def SendEther(self):
        web3 = Web3(Web3.HTTPProvider('https://ropsten.infura.io/v3/3c0b6b7eaed34d84894382a78aa4db18'))
        if self.ReceivingAddress.text() == '':
            self.Error.setText("To Who?")
        if self.AmountSent.text() == '':
            self.Error.setText("How Much?")
        if self.ReceivingAddress.text() == '' and self.AmountSent.text() == '':
            self.Error.setText("Fill Out Form")
        else:
            try:
                self.tx['to'] = self.ReceivingAddress.text()
                self.tx['value'] = web3.toWei(self.AmountSent.text(), 'ether')
                signed_tx = web3.eth.account.sign_transaction(self.tx, self.private_key1)
                tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
                self.Trans_Sent.setText("Transaction Sent")
                self.Trans_Hash.setText("Transaction Hash: " + HexBytes.hex(tx_hash))
            except ValueError:
                self.Trans_Sent.setText("Not Enough Funds Broke Boi")

class ReceiveETH(QDialog):
    def __init__(self, results):
        super(ReceiveETH, self).__init__()
        loadUi("Ether1Receive.ui", self)
        self.ClipBoard.clicked.connect(self.copy)
        addr = results[0][4]
        self.wallet_Address.setText(addr)
        qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
        )
        qr.add_data(addr)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert('RGB')
        img.save("QRcode.png")
        pixmap = QPixmap("./QRcode.png")
        self.QRcode.setPixmap(pixmap)




    def copy(self):
        cb = QApplication.clipboard()
        cb.clear(mode=cb.Clipboard)
        cb.setText(self.wallet_Address.text(), mode=cb.Clipboard)
        self.copied.setText("Address Copied")

app = QApplication(sys.argv)
welcome = EtherOne()
widget = QStackedWidget()
widget.addWidget(welcome)
widget.setFixedHeight(800)
widget.setFixedWidth(1200)
widget.show()
try:
    sys.exit(app.exec())
except:
    print("Exiting")
