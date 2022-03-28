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
                with open(os.path.join(sys.path[0], "server_private.pem"), "rb") as f:
                    key = f.read()
                    #create cipher block for decryption
                    privkey = RSA.import_key(key)
                    cipher_dec = PKCS1_OAEP.new(privkey)
                #import server public key
                with open(os.path.join(sys.path[0], "server_public.pem"), "rb") as f:
                    key = f.read()
                    #create cipher block for encryption
                    pubkey = RSA.import_key(key)
                    cipher_enc = PKCS1_OAEP.new(pubkey)

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
                    #generate sym pw and send to client
                    KeyLen = 256
                    sym_key = get_random_bytes(int(KeyLen/8))
                    encrypted_key = cipher_enc.encrypt(sym_key.encode('ascii'))
                    connectionSocket.send(encrypted_key)
                    #print on server screen
                    print("Connection Accepted and Symmetric Key Generated for client: username")
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

                #Receive client response and send menu
                encrypted_response = connectionSocket.recv(2048)
                response = unpad(cipher.decrypt(encrypted_response), 16).decode('ascii')
                menu = "Select the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\nchoice: "
                encrypted_menu = cipher.encrypt(pad(menu.encode('ascii'), 16))
                connectionSocket.send(encrypted_menu)

                #Receive client choice
                encrypted_choice = connectionSocket.recv(2048)
                choice = unpad(cipher.decrypt(encrypted_choice), 16).decode('ascii')

                #Perform the associated subprotocol
                while (int(choice) != 4):
                    #Sending Email Subprotocol
                    if (int(choice) == 1):
                        pass
                    #Viewing Inbox Subprotocol
                    elif (int(choice) == 2):
                        pass
                    #Viewing Email Subprotocol
                    elif (int(choice) == 3):
                        pass

                #Connection Termination Subprotocol
                connectionSocket.close()
                print("Terminating connection with " + username)
                return
                

            # 2: For parent process
            else:
                connectionSocket.close()
            


        #If error occurred during connection with client
        except socket.error as e:
            print("an error occurred while connecting: ", e)
            serverSocket.close()
            sys.exit(1)
        except:
            print('Goodbye')
            serverSocket.close() 
            sys.exit(0)


#----------
server()