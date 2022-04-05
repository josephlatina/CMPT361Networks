# Group Member Names: Joseph Latina, Andrew, Raphelos
# CMPT361 Project - Secure Mail Transfer Protocol

import json
import socket
import os, glob, datetime
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# String resizing for table pretty print
def tablestr(text,length):
    dif = int(length)-len(text)
    return text+(" "*dif*(dif > 0))

def viewinbox_handle(csock,cipher):
    # wait for server to sort list and send list length and pretty printing table lengths
    header_enc = csock.recv(2048)
    inbox_len, index_len, from_len, dt_len, title_len = (unpad(cipher.decrypt(header_enc), 16).decode('ascii')).split(";")

    # print table header
    header = tablestr("Index",index_len)+'    '+tablestr("From",from_len)+'    '+tablestr("DateTime",dt_len)+'    '+tablestr("Title",title_len)
    print(header)

    # receive each list item, display them as they are recieved 
    inbox = []
    for i in range(int(inbox_len)):
        next = csock.recv(2048)
        index, src, dt, title = (unpad(cipher.decrypt(next), 16).decode('ascii')).split(";")
        # print contents
        contents = tablestr(index,index_len)+'    '+tablestr(src,from_len)+'    '+tablestr(dt,dt_len)+'    '+tablestr(title,title_len)
        print(contents)
        inbox.append((index,src,dt,title))
        # signal the client is ready for the next list item
        csock.send("0".encode('ascii'))


def client():
    #Server Port
    serverPort = 13000

    #Prompt user for server name
    serverName = input("Enter the server IP or name: ")

    #Create client socket using IPv4 and TCP protocols
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print("Error in client socket creation:", e)
        sys.exit(1)

    #Connect client with the server
    try:
        clientSocket.connect((serverName, serverPort))

        #Ask user to enter credentials
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        user_pass = username + " " + password

        #import server public key
        with open(os.path.join(sys.path[0], "keys", "server_public.pem"), "rb") as f:
            key = f.read()
            #create cipher block for encryption
            pubkey = RSA.import_key(key)
            cipher_enc = PKCS1_OAEP.new(pubkey)

        #send username and pw to server (encrypted with server public key)
        encrypted_user_pass = cipher_enc.encrypt(user_pass.encode('ascii'))
        clientSocket.send(encrypted_user_pass)

        #accept server reply
        response = clientSocket.recv(2048)
        #if invalid user, terminate connection
        if (response == "Invalid username or password".encode('ascii')):
            print("Invalid username or password.\nTerminating.")
            clientSocket.close()
            return
        #otherwise, store the received symmetric key
        else:
            #import client private key
            clientkeypath = username + "_private.pem"
            with open(os.path.join(sys.path[0], "keys", clientkeypath), "rb+") as f:
                key = f.read()
                #create cipher block for encryption
                privkey = RSA.import_key(key)
                cipher_dec = PKCS1_OAEP.new(privkey)
            #decrypt symm key (decrypted with client private key)
            sym_key = cipher_dec.decrypt(response)

        #Generate ciphering block for symm key
        cipher = AES.new(sym_key, AES.MODE_ECB)
        #send "OK" message to server encrypted with symm key
        encrypted_menu = cipher.encrypt(pad("OK".encode('ascii'), 16))
        clientSocket.send(encrypted_menu)

        #Receive and print menu to user (decrypted with symm key)
        encrypted_menu = clientSocket.recv(2048)
        menu = unpad(cipher.decrypt(encrypted_menu), 16).decode('ascii')

        #Loop for user to interact with menu
        choice = input(menu)
        while (int(choice) != 4):
            #send user choice to server (encrypted with symm key)
            encrypted_choice = cipher.encrypt(pad(choice.encode('ascii'), 16))
            clientSocket.send(encrypted_choice)
            #start the associated subprotocols
            if (int(choice) == 1):
                pass
            elif (int(choice) == 2):
                viewinbox_handle(clientSocket,cipher)
            elif (int(choice) == 3):
                pass
            #prompt user again for choice
            choice = input(menu)

        #send user's choice of termination to server
        encrypted_choice = cipher.encrypt(pad(choice.encode('ascii'), 16))
        clientSocket.send(encrypted_choice)
        #commence connection termination subprotocol
        clientSocket.close()
        print("The connection is terminated with the server.")

    #If error occurred during connection with server
    except socket.error as e:
        print('An error occurred during connection: ', e)
        clientSocket.close()
        sys.exit(1)


#----------
client()