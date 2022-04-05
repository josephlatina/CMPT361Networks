# Group Member Names: Joseph Latina, Andrew, Raphael Wong
# CMPT361 Project - Secure Mail Transfer Protocol

import json
import socket
import os, glob, datetime
from datetime import datetime
from sqlite3 import connect
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def server():
    #server port
    serverPort = 13000

    #Create server socket that uses IPV4 and TCP protocols
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print("Error in server socket creation:", e)
        sys.exit(1)

    #Bind port number to server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print("Error in server socket binding:", e)
        sys.exit(1)

    #Let Server Socket listen up to any five client connections simultaneously at a time
    serverSocket.listen(5)
    print("The server is ready to accept connections")
    
    #loop to go through multiple clients
    while 1:
        #try to connect with current client
        try:
            #Server accepts client connection
            connectionSocket, addr = serverSocket.accept()

            #Create a fork
            pid = os.fork()

            # 1: For child process, it will handle current client interaction
            if (pid == 0):
                #Terminate child process connection to server socket
                serverSocket.close()

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

                #Create 5 directory inboxes for the 5 clients, skips this step if they already exists
                if not os.path.exists("client1"):
                    os.mkdir("client1")
                    os.mkdir("client2")
                    os.mkdir("client3")
                    os.mkdir("client4")
                    os.mkdir("client5")

                #Receive client response and send menu
                encrypted_response = connectionSocket.recv(2048)
                response = unpad(cipher.decrypt(encrypted_response), 16).decode('ascii')
                menu = "Select the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\n\n\tchoice: "
                encrypted_menu = cipher.encrypt(pad(menu.encode('ascii'), 16))
                connectionSocket.send(encrypted_menu)

                #Receive client choice
                encrypted_choice = connectionSocket.recv(2048)
                choice = unpad(cipher.decrypt(encrypted_choice), 16).decode('ascii')

                #Perform the associated subprotocol
                while (int(choice) != 4):
                    #Sending Email Subprotocol
                    if (int(choice) == 1):
                        encrypted_response = connectionSocket.recv(2048)
                        response = unpad(cipher.decrypt(encrypted_response), 16).decode('ascii')

                        #break up the message to obtain certain parts as listed below
                        responseList = response.split('\n')
                        #From:
                        fromUser = responseList[0]
                        #To:
                        destinations = responseList[1]
                        #Title:
                        title = responseList[2]
                        #List of client(s) to send email to
                        destinationsList = destinations.split(';')

                        #Need the content length to ensure safe recieving from client
                        contentLength = int(responseList[3])

                        #Need this for summary message
                        contentLengthMessage = responseList[3]

                        #send the okay to recieve the content (dummy send)
                        encryptedMessage = cipher.encrypt(pad("ok".encode('ascii'), 16))
                        connectionSocket.send(encryptedMessage)

                        #Logic for safely recieving content message that may exceed 2048 bytes from client
                        content = ""
                        while contentLength > 0:
                            if contentLength > 2048:
                                encrypted_response = connectionSocket.recv(2048)
                                response = cipher.decrypt(encrypted_response).decode('ascii')
                                content += response
                                contentLength -= 2048
                            else:
                                encrypted_response = connectionSocket.recv(2048)
                                response = unpad(cipher.decrypt(encrypted_response), 16).decode('ascii')
                                content += response
                                contentLength -= 2048

                        
                        #The time message is recieved
                        timeRecieved = str(datetime.now())
                        
                        #The email to be saved in a clients inbox
                        messageToSave = "From: " + fromUser + "\nTo: " + destinations + "\nTime and Date Recieved: " + timeRecieved + "\nTitle: " + title + "\nContent Length: " + contentLengthMessage + "\nContents:\n" + content

                        #print a message that says an email from user to destination(s) has content length of #.
                        messageSent = "An email from " + fromUser + " is sent to " + destinations + " has a content length of " + contentLengthMessage + " ."             
                        print(messageSent)

                        #saving email to clients inbox
                        for user in destinationsList:
                            if os.path.exists(user):
                                with open(os.path.join(user,fromUser + "_" + title + ".txt"),'w') as fp:
                                    fp.write(messageToSave)
                                    fp.close()
                            
                    #Viewing Inbox Subprotocol
                    elif (int(choice) == 2):
                        pass
                    #Viewing Email Subprotocol
                    elif (int(choice) == 3):
                        #recieve index
                        encryptedIndex = connectionSocket.recv(2048)
                        index = unpad(cipher.decrypt(encryptedIndex), 16).decode('ascii')

                        #look for title
                        

                        pass
                    #Receive client choice
                    encrypted_choice = connectionSocket.recv(2048)
                    choice = unpad(cipher.decrypt(encrypted_choice), 16).decode('ascii')

                #Connection Termination Subprotocol
                print("Terminating connection with " + username)
                connectionSocket.close()
                return
                

            # 2: For parent process
            else:
                connectionSocket.close()
            


        #If error occurred during connection with client
        except socket.error as e:
            print("an error occurred while connecting: ", e)
            serverSocket.close()
            sys.exit(1)
        # except:
        #     print('Goodbye')
        #     serverSocket.close() 
        #     sys.exit(0)


#----------
server()
