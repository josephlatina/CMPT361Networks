# Group Member Names: Joseph Latina, Andrew Numrich, Raphael Wong
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
sys.path.append("../")
from EnhancedSocket import EnhancedSocket, EnhancedClient, EnhancedServer

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

    # signal the client is ready to recieve list data
    csock.send("0".encode('ascii'))

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

def connection_handle(sock):
    #Receive and print menu to user (decrypted with symm key)
    menu = sock.recv(2048).decode('ascii')
    #Loop for user to interact with menu
    choice = input(menu)
    while (int(choice) != 4):
        #send user choice to server (encrypted with symm key)
        sock.send(choice.encode('ascii'))
        #start the associated subprotocols
        
        if (int(choice) == 1):
            fullMessage = ""
            destinationMessage = GetDestination()
            titleMessage = GetTitle()
            contentMessage = GetContent()
            contentLength = len(contentMessage)
            fullMessage = username + '\n' +destinationMessage + '\n' + titleMessage + '\n' + str(contentLength)
            sock.send(fullMessage.encode('ascii'))
            
            #Recieve the okay to send content (dummy recv)
            decryptedMessage = clientSocket.recv(2048).decode('ascii')
            #send content to server
            sock.send(contentMessage.encode('ascii'))
            print("The message is sent to the server.")

        elif (int(choice) == 2):
            viewinbox_handle(sock)
        elif (int(choice) == 3):
            #Get the index the user wishes to view and send it over
            viewIndex = input("Enter the email index you wish to view: ")
            sock.send(viewIndex.encode('ascii'))
            
            
            #Recieve the size of file to prepare for safe recieving of actual file
            sizeMessage = sock.recv(2048).decode('ascii')
            fileSize = int(sizeMessage)
            #sends the okay to send file (dummy send)
            sock.send("Ok".encode('ascii'))
            fileToPrint = "\n"
            while fileSize > 0:
                if fileSize > 2048:
                    response = sock.recv(2048).decode('ascii')
                    fileToPrint += response
                    fileSize -= 2048
                else:
                    response = sock.recv(2048).decode('ascii')
                    fileToPrint += response
                    fileSize -= 2048
            
            print(fileToPrint)              
        #prompt user again for choice
        choice = input(menu)
    #send user's choice of termination to server
    sock.send(choice.encode('ascii'))
    #commence connection termination subprotocol
    sock.close()
    print("The connection is terminated with the server.")

def client():
        #Server Port
        serverPort = 13000

        #Prompt user for server name
        serverName = input("Enter the server IP or name: ")

        #Ask user to enter credentials
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        EnhancedClient(connection_handle,serverName,serverPort,username,password)

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
        if titleMessage == "":
            print("Title cannot be empty. Try Again.")
        elif len(titleMessage) > 100:
            print("Title exceeds maximum length. Try Again.")
        else:
            break
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
                
                elif file_size == 0:
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
            
            elif len(contentMessage) == 0:
                print("message content is empty")
            
            else:
                break
    return contentMessage

#----------
client()
