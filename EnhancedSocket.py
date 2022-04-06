# Group Member Names: Joseph Latina, Andrew Numrich, Raphael Wong
# CMPT361 Project - Secure Mail Transfer Protocol

import json
import socket
import os, glob, datetime
from datetime import datetime
from sqlite3 import connect
import sys
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS



# Socket enhancement wrapper over an active socket connection. 
class EnhancedSocket:

    # A wrapper around a typical socket connection that manages integrity hashing.
    #   connectionSocket: An insecure socket connection which implements send() and recv() 
    #   cipher: The RSA cipher
    def __init__(self,connectionSocket,cipher):
        self.sock = connectionSocket
        self.cipher = cipher

    def encrypt(self,bytes):
        return self.cipher.encrypt(pad(bytes, 16))
    
    def decrypt(self,enc_bytes):
        return unpad(self.cipher.decrypt(self.sock.recv(enc_bytes)), 16)
    
    def send(self,bytes):
        # create hash and sign
        hash = SHA256.new(bytes)
        sig = self.cipher.sign(hash)
        # send signature
        self.sock.send(self.cipher.encrypt(sig))
        # send encrypted bytes
        self.sock.send(self.encrypt(bytes)) 
        return

    def recv(self,maxbytes):
        # recieve signature and bytes, decrypt both
        sig = self.decrypt(self.sock.recv(32))
        bytes = self.decrypt(self.sock.recv(maxbytes)) 

        # generate a hash from decrypted bytes
        hash = SHA256.new(bytes)

        # verify hash
        try:
            self.cipher.verify(h, sig)
        except ValueError:
            print("Error: Hash signature does not match.")

        return bytes
    
    def close(self):
        self.sock.close()
        return

class EnhancedServer:
    def __init__(self,max_clients):
        #server port
        serverPort = 13000

        self.max_clients = max_clients 

        #Create server socket that uses IPV4 and TCP protocols
        try:
            self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as e:
            print("Error in server socket creation:", e)
            sys.exit(1)

        #Bind port number to server socket
        try:
            self.serverSocket.bind(('', serverPort))
        except socket.error as e:
            print("Error in server socket binding:", e)
            sys.exit(1)

    
    # Set a callback and start listening for clients
    #   callback: Must be a function that takes an EnhancedSocket as a parameter.
    def listen(self,callback):

        #Let Server Socket listen up to any max number of client connections simultaneously at a time
        self.serverSocket.listen(self.max_clients)
        print("The server is ready to accept connections")

        #try to connect with current client
        try:
            #Server accepts client connection
            connectionSocket, addr = self.serverSocket.accept()

            #Create a fork
            pid = os.fork()

            # 1: For child process, it will handle current client interaction
            if (pid == 0):
                #Terminate child process connection to server socket
                self.serverSocket.close()

                #import server private key
                with open(os.path.join(sys.path[0], "keys", "server_private.pem"), "rb") as f:
                    key = f.read()
                    #create cipher block for decryption
                    privkey = RSA.import_key(key)
                    cipher_dec = PKCS1_OAEP.new(privkey)

                #Receive client message and decrypt message
                encrypted_message = connectionSocket.recv(2048)
                decrypted_message = cipher_dec.decrypt(encrypted_message).decode('ascii')
                decrypted_data = decrypted_message.split(" ")
                username = decrypted_data[0]
                password = decrypted_data[1]

                #Authenticate users
                counter = 0
                with open(os.path.join(sys.path[0], "user_pass.json"), "rb") as json_file:
                    user_pass = json.load(json_file)
                for user, pw in user_pass.items():
                    if (user == username and pw == password):
                        counter += 1
                        break
                #If there is a match, send symmetric pw
                if (counter == 1):
                    #import client public key
                    clientkeypath = username + "_public.pem"
                    with open(os.path.join(sys.path[0], "keys", clientkeypath), "r") as f:
                        key = f.read()
                        #create cipher block for encryption
                        pubkey = RSA.import_key(key)
                        cipher_enc = PKCS1_OAEP.new(pubkey)

                    #generate sym pw and send to client
                    KeyLen = 256
                    sym_key = get_random_bytes(int(KeyLen/8))
                    encrypted_key = cipher_enc.encrypt(sym_key)
                    connectionSocket.send(encrypted_key)
                    #print on server screen
                    print("Connection Accepted and Symmetric Key Generated for client: "  + username)
                #Otherwise,
                else:
                    #send error message
                    connectionSocket.send("Invalid username or password".encode('ascii'))
                    #print error message to server
                    print("The received client information: " + username + " is invalid (Connection Terminated).")
                    #terminate connection
                    connectionSocket.close()
                    return

                #Generate ciphering block for symm key
                cipher = AES.new(sym_key, AES.MODE_ECB)

                # Perform the client handling callback
                callback(EnhancedSocket(connectionSocket,cipher))               

            # 2: For parent process
            else:
                connectionSocket.close()

        #If error occurred during connection with client
        except socket.error as e:
            print("an error occurred while connecting: ", e)
            serverSocket.close()
            sys.exit(1)

class EnhancedClient:

    def __init__(self):
