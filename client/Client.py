# Group Member Names: Joseph Latina, Andrew, Raphael Wong
# CMPT361 Project - Secure Mail Transfer Protocol

import email
import json
from ossaudiodev import control_names
import socket
import os, glob, datetime
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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
                fullMessage = ""
                destinationMessage = GetDestination()
                titleMessage = GetTitle()
                contentMessage = GetContent()
                contentLength = len(contentMessage)

                fullMessage = username + '\n' +destinationMessage + '\n' + titleMessage + '\n' + str(contentLength)

                encryptedMessage = cipher.encrypt(pad(fullMessage.encode('ascii'), 16))
                clientSocket.send(encryptedMessage)
                
                #Recieve the okay to send content (dummy recv)
                decryptedMessage = clientSocket.recv(2048)
                message = unpad(cipher.decrypt(encrypted_menu), 16).decode('ascii')

                #send content to server
                encryptedMessage = cipher.encrypt(pad(contentMessage.encode('ascii'), 16))
                clientSocket.send(encryptedMessage)

                print("The message is sent to the server.")
 
            elif (int(choice) == 2):
                pass
            elif (int(choice) == 3):
                #Get the index the user wishes to view and send it over
                viewIndex = input("Enter the email index you wish to view: ")
                encryptedMessage = cipher.encrypt(pad(viewIndex.encode('ascii'), 16))
                clientSocket.send(encryptedMessage)               

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

#Helper function for Sending Email Subprotocol that prompts the user for the Destination the email is going to be sent to
def GetDestination():
    while True:
        flag = 0
        destinationMessage = input("Enter destinations (seperated by ;): ")
        destinationsList = destinationMessage.split(';')
        emailList = ['client1','client2','client3','client4','client5']
        for destination in destinationsList:
            if destination not in emailList:
                flag = 1
        if flag == 0:
            break
        else:
            print("One or more email does not exist")
    return destinationMessage

#Helper function for Sending Email Subprotocol that prompts the user for the Title of email
def GetTitle():
    while True:
        titleMessage = input("Enter the title: ")
        if titleMessage != "":
            break
        else:
            print("Title cannot be empty. Try Again.")
    return titleMessage

#Helper function for Sending Email Subprotocol to get the contents the user wants to send
def GetContent():
    while True:
        question = input("Would you like to load contents from a file? (Y/N) ")
        
        if question == "Y" or question == "y":
            filename = input("Enter the filename: ")

            if os.path.isfile(filename):
                file_size = os.path.getsize(filename)

                if file_size > 1000000:
                    print("message content exceeds maximum length.")
                
                if file_size == 0:
                    print("message content is empty")
                
                else:
                    file = open(filename,'r')
                    contentMessage = file.read()
                    break
            else:
                print("File does not exist.")
                    
                    
        elif question == "N" or question == "n":
            contentMessage = input("Enter the message contents: ")
            
            if len(contentMessage) > 1000000:
                print("message content exceeds maximum length.")
            
            if len(contentMessage) == 0:
                print("message content is empty")
            
            else:
                break
    return contentMessage

#----------
client()
