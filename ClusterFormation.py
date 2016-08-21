import Crypto
from Crypto import Random
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet
import sys
import dill
import ast
import base64
import os
from uuid import getnode as get_mac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import b64encode

from PyQt4 import QtGui,QtCore
from PyQt4.QtGui import *

userName = ["None"]*10
currentUserName = "None"

def file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1

def ClusterFormation(fname):
    size = file_len(fname)
    fldatalist = []
    floatingdata = {}

    
    with open(fname) as f:
        for line in f:
            listValue = line.split(":")
            veid = listValue[0]
            lat = float(listValue[1])
            lng = float(listValue[2])
            speed = float(listValue[3])
            fldatalist.append({'Vehicle ID' : veid, 'Latitude' : lat , 'Longitude' : lng, 'Speed' : speed})

    return fldatalist


    
def writeUserName(userName, fileName):
##    print(userName)
##    print(fileName)
    writeFile = open(fileName+".txt",'a')
    writeFile.write(userName + "\n")

    writeFile.close()

def userNameExists(username):
    readFile = open("userPasswordLog.txt",'r')
    for line in readFile:
        string = line
        listValue = string.split(":")
        if(listValue[0] == username):
            
            return 'true'
    return 'false'

def retrieveUserName(username):
    readFile = open("userPasswordLog.txt",'r')
    for line in readFile:
        string = line
        listValue = string.split(":")
        if(listValue[0] == username):
            return string
    
def Encryption(string, newName):
    AESkey = Fernet.generate_key()
    aes_string = AESkey.decode('unicode_escape') #To convert bytes to unicode plain text.

    writeFile = open(newName+".txt",'w')
    cipher_suite = Fernet(AESkey)
    with open(string) as f:
        for line in f:
            string = line
            cipher_text = cipher_suite.encrypt(string.encode('UTF-8'))
            intermediate_string = cipher_text.decode('unicode_escape')
            writeFile.write(intermediate_string + "\n")      
    writeFile.close()
    f.close()


    key = RSA.importKey(b'-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQCcif1atcd0ct88NHYsvqOzJew5czCiBhPT/NqAXjHKabY4qGgf\nMTGd+WTcz1KXVKwa7E/f93JozAcAf682i89tj3kn6ODwNi//jdq+JoVSQ/K07UYY\ntYYEg4eh2X+ZofyOK+X+AViNz31i+apDJPaQTOXn/WFPjZIrXB+0+JVgnQIDAQAB\nAoGARUD/J1x4i1ouzPHgvlbxEVbbtWbywxuxNf4NpPEHUieGiHZo6jPXYa5uIwpN\n3cmGArs9czaEFTz+dAgJOjaMY5j456sBtpSTvS9gFlTLv0JfrRBRzCX9JLpL0oD+\ncXWoAGuuL+dRd9dQBpAkvc4CMCL3aNRL6qLW4PnKZC7+sMECQQDCDQYnSff3B1jn\nga66AAu//Xbn/A7PlJrT2u/PmF4vD9tzKtQNf78KCD/gT27ep6zIojpam2fhtPlC\n8yzsyLDZAkEAzoNG5Lx7D4w7L53KfmQBd+gJ1sAniBe1YHzQuPboxPjmUtEQgrHX\nk4B+KgNiFgdsFG9eNYLmLmuHCAhm1dOTZQJBAIJNSo+BTN908I7r9s7xDvLJmVmn\nWK6s49ZUkml8r+m8JSjNXnz+BeMPrQzLafBa+Vv0C2kiJ3xZEHOTZNxO2ukCQCXf\nd3ntgxgX3Kbf5koFpytJV7yVoupXhsD6QwEY7xlomDzp8IA3g1SexQSJeEyX8d9R\niVKA/hvXRn1XpRxj3+0CQGPmggs7zsW7GW8s0aBchYx3fXMTWRgOq0dhZS3iMZaX\ndewUAFjMitCDCi6PxqAio2HD3hezGv8WtA/J+juvHsI=\n-----END RSA PRIVATE KEY-----')
    publickey = key.publickey() # pub key export for exchange


    ##Write the public key
    writeFile = open("RSAPublicKey.txt",'wb')
    dill.dump(publickey, writeFile)   
    writeFile.close()



    encrypted = publickey.encrypt(aes_string.encode('utf-8'), 1024)

    ## Writing the encrypted key into a text file.

    #print(encrypted)
    writeFile = open("RSAEncryptedText.txt",'w')
    writeFile.write(str(encrypted))  #Append message
    writeFile.close()


## RSA Decryption.
def Decryption(fileName):

##    with open(fname, 'rb') as fh:
##        first = next(fh).decode()
##        fh.seek(-1024, 2)
##        last = fh.readlines()[-1].decode()
##
    i = 0
    flag = 0

    while i < len(userName) :
        if(currentUserName == userName[i]):
            print("I found the treasure at")
            print(i)
            flag = 1
            break
        i = i + 1

    if flag != 1:
        print("OOPS")
        return
    
    print("Processing Decryption")
    key = RSA.importKey(b'-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQCcif1atcd0ct88NHYsvqOzJew5czCiBhPT/NqAXjHKabY4qGgf\nMTGd+WTcz1KXVKwa7E/f93JozAcAf682i89tj3kn6ODwNi//jdq+JoVSQ/K07UYY\ntYYEg4eh2X+ZofyOK+X+AViNz31i+apDJPaQTOXn/WFPjZIrXB+0+JVgnQIDAQAB\nAoGARUD/J1x4i1ouzPHgvlbxEVbbtWbywxuxNf4NpPEHUieGiHZo6jPXYa5uIwpN\n3cmGArs9czaEFTz+dAgJOjaMY5j456sBtpSTvS9gFlTLv0JfrRBRzCX9JLpL0oD+\ncXWoAGuuL+dRd9dQBpAkvc4CMCL3aNRL6qLW4PnKZC7+sMECQQDCDQYnSff3B1jn\nga66AAu//Xbn/A7PlJrT2u/PmF4vD9tzKtQNf78KCD/gT27ep6zIojpam2fhtPlC\n8yzsyLDZAkEAzoNG5Lx7D4w7L53KfmQBd+gJ1sAniBe1YHzQuPboxPjmUtEQgrHX\nk4B+KgNiFgdsFG9eNYLmLmuHCAhm1dOTZQJBAIJNSo+BTN908I7r9s7xDvLJmVmn\nWK6s49ZUkml8r+m8JSjNXnz+BeMPrQzLafBa+Vv0C2kiJ3xZEHOTZNxO2ukCQCXf\nd3ntgxgX3Kbf5koFpytJV7yVoupXhsD6QwEY7xlomDzp8IA3g1SexQSJeEyX8d9R\niVKA/hvXRn1XpRxj3+0CQGPmggs7zsW7GW8s0aBchYx3fXMTWRgOq0dhZS3iMZaX\ndewUAFjMitCDCi6PxqAio2HD3hezGv8WtA/J+juvHsI=\n-----END RSA PRIVATE KEY-----')

    f = open('RSAEncryptedText.txt', 'r')
    message = f.read()

    decrypted = key.decrypt(ast.literal_eval(str(message)))
##    print(decrypted)
    
    #At this point, the key is decrypted, AES Decryption can now begin.
    ## AES Decryption
    decipher_suite = Fernet(decrypted)

    content = []

    with open(fileName,'r') as f:
        for line in f:
            string = line
            decipher_text = decipher_suite.decrypt(string.encode('UTF-8'))
            intermediate_string = decipher_text.decode('unicode_escape')
            print(intermediate_string)
            content.append(intermediate_string)

    f.close()

    return content


def SaltedPassword(username,passwordString):
    password = bytes(passwordString, 'utf-8')
    salt = os.urandom(16)
    
    token = b64encode(salt).decode('utf-8')
    saltToken = bytes(token, 'utf-8')
    
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=saltToken,iterations=100000,backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))
    tokenkey = b64encode(key).decode('utf-8')    

    writeFile = open("userPasswordLog.txt",'a')
    writeFile.write(username + ":" + token + ":" + tokenkey + ":" + str(get_mac()) + "\n")
    writeFile.close()

def VerifyPassword(passwordString, saltValue, HashValue, MAC_ADDRESS):
    
    password = bytes(passwordString, 'utf-8')
    salt = bytes(saltValue, 'utf-8')
    
    token = b64encode(salt).decode('utf-8')

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))
    tokenkey = b64encode(key).decode('utf-8')    
    if tokenkey == HashValue:
        if(MAC_ADDRESS == get_mac()):
            return 'true'
        else:
            
            print('Mismatch of MAC ADDRESS')
            return 'false'
    else:
        print('Mismatch of salts')
        return 'false'

    

class ClusterDetails(QtGui.QDialog):
    
    def __init__(self, parent = None,text):
        super(ClusterDetails, self).__init__(parent)
        self.setStyleSheet('font-size: 14pt; font-family: Courier;')
        
        self.initUI()
        
    def initUI(self):


        self.setWindowIcon(QtGui.QIcon('data_encryption.png'))

        lbl0 = QtGui.QLabel('Cluster Details', self)
        lbl0.move(170, 10)

        lbl1 = QtGui.QLabel('VehicleID', self)
        lbl1.move(15, 90)
        self.qle1 = QtGui.QLineEdit(self)
        self.qle1.move(200,90)
        
        lbl2 = QtGui.QLabel('Latitude', self)
        lbl2.move(15, 140)
        self.qle2 = QtGui.QLineEdit(self)
        self.qle2.move(200,140)

        lbl3 = QtGui.QLabel('Longitude', self)
        lbl3.move(15, 190)
        self.qle3 = QtGui.QLineEdit(self)
        self.qle3.move(200,190)
        
        lbl4 = QtGui.QLabel('Speed', self)
        lbl4.move(15, 240)
        self.qle4 = QtGui.QLineEdit(self)
        self.qle4.move(200,240)

        


        btn = QtGui.QPushButton('Add to Cluster', self)
        btn.move(200, 400)
        self.connect(btn, QtCore.SIGNAL('clicked()'), self.AppendDetails)
       
        self.setGeometry(250, 250, 500, 440)
        self.setWindowTitle('JJRP Systems')    
        self.show()

    def SignUp(self):
        with open(fname) as f:
            
        super(ClusterDetails, self).accept()

class ClusterSkeleton(QtGui.QDialog):
    
    def __init__(self,parent = None):
        super(ClusterSkeleton, self).__init__(parent)
        self.setStyleSheet('font-size: 18pt; font-family: Courier;')
        
        self.initUI()
        
    def initUI(self):
        


        self.setWindowIcon(QtGui.QIcon('data_encryption.png'))

        lbl0 = QtGui.QLabel('Cluster Basics', self)
        lbl0.move(140, 30)

        self.lbl1 = QtGui.QLabel('Name of Cluster', self)
        self.lbl1.move(15, 90)

        self.qle = QtGui.QLineEdit(self)
        self.qle.move(240,90)

        self.lbl2 = QtGui.QLabel('Vehicles in Cluster', self)
        self.lbl2.move(15, 140)

        self.qle1 = QtGui.QLineEdit(self)
        self.qle1.move(200,140)
        btn = QtGui.QPushButton('Form Cluster', self)
        btn.move(350, 200)
        self.connect(btn, QtCore.SIGNAL('clicked()'), self.formCluster)

        
       
        self.setGeometry(250, 250, 500, 240)
        self.setWindowTitle('JJRP Systems')    
        self.show()

    def formCluster(self):

        for (i in range(int(self.qle1.text()))):

            
        
        

    
class PostLogin(QtGui.QDialog):
    
    def __init__(self,parent = None):
        super(PostLogin, self).__init__(parent)
        self.setStyleSheet('font-size: 18pt; font-family: Courier;')
        
        self.initUI()
        
    def initUI(self):

        self.setWindowIcon(QtGui.QIcon('data_encryption.png'))        
        
        btn0 = QtGui.QPushButton('Encrypt File', self)
        btn0.move(20, 30)       
        self.connect(btn0, QtCore.SIGNAL('clicked()'), self.EncryptFile)
        
        btn1 = QtGui.QPushButton('Decrypt File', self)
        btn1.move(20, 80)
        self.connect(btn1, QtCore.SIGNAL('clicked()'), self.DecryptFile)
        
        self.setGeometry(300, 300, 300, 150)
        self.setWindowTitle('Dashboard')    
        self.show()
        
    def EncryptFile(self):
        self.EncryptWindowInstance = EncryptWindow(self)
        self.EncryptWindowInstance.exec_()
        super(PostLogin, self).accept()

    def DecryptFile(self):
        self.EncryptWindowInstance = DecryptWindow(self)
        self.EncryptWindowInstance.exec_()
        super(PostLogin, self).accept()
        


class Login(QtGui.QDialog):
    
    def __init__(self,parent = None):
        super(Login, self).__init__(parent)
        self.setStyleSheet('font-size: 18pt; font-family: Courier;')
        
        self.initUI()
        
    def initUI(self):
        


        self.setWindowIcon(QtGui.QIcon('data_encryption.png'))

        lbl0 = QtGui.QLabel('Login Credentials', self)
        lbl0.move(140, 30)

        self.lbl1 = QtGui.QLabel('Username', self)
        self.lbl1.move(15, 90)

        self.qle = QtGui.QLineEdit(self)
        self.qle.move(200,90)

        self.lbl2 = QtGui.QLabel('Password', self)
        self.lbl2.move(15, 140)

        self.qle1 = QtGui.QLineEdit(self)
        self.qle1.setEchoMode(QtGui.QLineEdit.Password)
        self.qle1.move(200,140)
        btn = QtGui.QPushButton('Sign In', self)
        btn.move(350, 200)
        self.connect(btn, QtCore.SIGNAL('clicked()'), self.handleLogin)

        
       
        self.setGeometry(250, 250, 500, 240)
        self.setWindowTitle('Tariang Login Systems')    
        self.show()

    def handleLogin(self):

        if(userNameExists(self.qle.text())):
            
            string = retrieveUserName(self.qle.text())
            listValue = string.split(":")
            saltValue = listValue[1]
            hashValue = listValue[2]
           
            passwordstring = VerifyPassword(self.qle1.text(),saltValue, hashValue, get_mac())

            if passwordstring == 'false':
                
               
                QtGui.QMessageBox.warning(self, 'Error', 'Invalid Login')
            else:
               global currentUserName
               currentUserName = self.qle.text()
               self.PostLoginWindow = PostLogin(self)
               self.PostLoginWindow.exec_()
               super(Login, self).accept()
##            

        else:
            QtGui.QMessageBox.warning(self, 'Error', 'Invalid Login')


class SendingWindow(QtGui.QDialog):
    
    def __init__(self, parent, fileName = 'No File Selected' ):
        super(SendingWindow, self).__init__(parent)
        self.setStyleSheet('font-size: 18pt; font-family: Courier;')
        self.filename = fileName
        self.initUI()
        self.userNames = [None]*10
        
    def initUI(self):


        self.setWindowIcon(QtGui.QIcon('data_encryption.png'))

        lbl0 = QtGui.QLabel('Send To', self)
        lbl0.move(210, 30)

        self.lbl1 = QtGui.QLabel('Username', self)
        self.lbl1.move(15, 90)

        self.qle = QtGui.QLineEdit(self)
        self.qle.move(200,90)


        btn = QtGui.QPushButton('Send', self)
        btn.move(350, 200)

        self.connect(btn, QtCore.SIGNAL('clicked()'), self.sendingDocument)
        self.setGeometry(250, 250, 500, 240)
        self.setWindowTitle('Tariang Login Systems')    
        self.show()
        
    def sendingDocument(self):

        self.userNames = self.qle.text().split()
        global userName
        
        userName = self.userNames
        print(userName)
        super(SendingWindow, self).accept()
        


    
class EncryptWindow(QtGui.QDialog):
    
    
    def __init__(self, parent = None):
        super(EncryptWindow, self).__init__(parent)
        self.setStyleSheet('font-size: 18pt; font-family: Courier;')
        
        self.initUI()
        
    def initUI(self):
        


        self.setWindowIcon(QtGui.QIcon('data_encryption.png'))

        lbl1 = QtGui.QLabel('File Path:', self)
        lbl1.move(15, 90)

        btn0 = QtGui.QPushButton('Choose File', self)
        btn0.move(10, 30)
        self.connect(btn0, QtCore.SIGNAL('clicked()'), self.get_fname)

        self.FileLine0 = QtGui.QLineEdit(self)
        self.FileLine0.move(200, 90)
        self.FileLine0.setText('No file selected')

        lbl1 = QtGui.QLabel('New File :', self)
        lbl1.move(15, 140)

        self.FileLine1 = QtGui.QLineEdit(self)
        self.FileLine1.move(200, 140)

        btn1 = QtGui.QPushButton('Encrypt', self)
        btn1.move(250, 240)
        self.connect(btn1, QtCore.SIGNAL('clicked()'), self.encrypt_file)

        self.setGeometry(250, 250, 500, 300)
        self.setWindowTitle('Encrypt a file')    
        self.show()

        

    def get_fname(self):
        
        fname = QtGui.QFileDialog.getOpenFileName(self, 'Select file')

        if fname:
            self.FileLine0.setText(fname)
        else:
            self.FileLine0.setText('No file selected')

    def encrypt_file(self):
        Encryption(self.FileLine0.text(),self.FileLine1.text())
        
        self.SendingWindowBrowser = SendingWindow(self,self.FileLine1.text())
        
        self.SendingWindowBrowser.exec_()
        super(EncryptWindow, self).accept()
        
        
class DecryptWindow(QtGui.QDialog):
    
    
    def __init__(self, parent = None):
        super(DecryptWindow, self).__init__(parent)
        self.setStyleSheet('font-size: 18pt; font-family: Courier;')
        self.initUI()
    def initUI(self):
        


        self.setWindowIcon(QtGui.QIcon('data_encryption.png'))

        lbl1 = QtGui.QLabel('File Path:', self)
        lbl1.move(15, 90)

        btn0 = QtGui.QPushButton('Choose File', self)
        btn0.move(10, 30)
        self.connect(btn0, QtCore.SIGNAL('clicked()'), self.get_fname)

        self.FileLine0 = QtGui.QLineEdit(self)
        self.FileLine0.move(200, 90)
        self.FileLine0.setText('No file selected')

        self.textbox = QListWidget(self)
        self.textbox.move(100, 220)
        self.textbox.resize(280,550)


        btn1 = QtGui.QPushButton('Decrypt', self)
        btn1.move(200, 150)
        self.connect(btn1, QtCore.SIGNAL('clicked()'), self.decrypt_file)

        self.setGeometry(250, 250, 500, 600)
        self.setWindowTitle('Decrypt a file')    
        self.show()

        

    def get_fname(self):
        
        fname = QtGui.QFileDialog.getOpenFileName(self, 'Select file')

        if fname:
            self.FileLine0.setText(fname)
        else:
            self.FileLine0.setText('No file selected')

    def decrypt_file(self):
        listValue = Decryption(self.FileLine0.text())
        if(listValue == None):
            self.textbox.addItem("Unauthorized Access")
        
        else:
            print('Access Granted')
            for i in listValue:
                self.textbox.addItem(i)

        
                



class MainMenu(QtGui.QWidget):
    
    def __init__(self):
        super(MainMenu, self).__init__()
        self.setStyleSheet('font-size: 20pt; font-family: Courier;')
        
        self.initUI()
        
    def initUI(self):
        
        QtGui.QToolTip.setFont(QtGui.QFont('SansSerif', 10))
        
        
        btn0 = QtGui.QPushButton('Log In', self)
        btn0.move(80, 30)
        self.connect(btn0, QtCore.SIGNAL('clicked()'), self.Login)
        
        btn1 = QtGui.QPushButton('Sign Up', self)
        btn1.resize(btn1.sizeHint())
        btn1.move(80, 80)
        self.connect(btn1, QtCore.SIGNAL('clicked()'), self.SignUp)
        
        btn2 = QtGui.QPushButton('Quit', self)
        btn2.resize(btn2.sizeHint())
        btn2.move(100, 130)
        self.connect(btn2, QtCore.SIGNAL('clicked()'), self.Quit)
        
        self.setGeometry(300, 300, 300, 200)
        self.setWindowTitle('Main Window')    
        self.show()

    
    def Login(self):

        self.LoginWindow = Login(self)
        self.LoginWindow.exec_()
        
    

    
    def SignUp(self):
        self.SetupWindow = SetupWindow(self)
        self.SetupWindow.exec_()
         
        
        

    
    def Quit(self):
        QtCore.QCoreApplication.instance().quit()
        
def main():
    
    app = QtGui.QApplication(sys.argv)
    ex = MainMenu()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()



            
