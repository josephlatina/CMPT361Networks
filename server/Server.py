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

user_inbox = {}

# Insert at index in an array, pushing following elements to the right
def insert_at(arr, item, index):
    return arr[0:index] + [item] + arr[index:len(arr)]

# Extract header information from an email file
def read_email_header(filepath):
    # extract each string from the desired file
    with open(filepath, "r") as f:
        srcusr = f.readline()[len("From: "):].replace('\n',"") # source username
        f.readline() # (skip) destination username
        dtstr = f.readline()[len("Time and Date recieved: "):].replace('\n',"") # date/time
        title = f.readline()[len("Title: "):].replace('\n',"") # title
        f.close()
    dt = datetime.fromisoformat(dtstr) 
    return (srcusr,dt,title)

# Get a filename by an email's index in the user's inbox
def get_file(username,index):
    global user_inbox
    
    # load the user's inbox data if it isnt loaded yet
    if not user_inbox.has_key(username):
        cache_inbox(username)
    
    # get pointers to inbox and the email at the desired index 
    inbox = user_inbox[username][1]
    src,dt,title = inbox[index]

    return src+'_'+title+".txt"

# Loads the user's inbox data and caches it to user_inbox
def cache_inbox(username):
    global user_inbox
    inbox = []
    # intialize pretty printing table lengths and index counter
    index_len = len("Index")
    from_len = len("From")
    dt_len = len("DateTime")
    title_len = len("Title")
    email_index = 0

    # walk user's directory and fetch email file data
    for rootdir, childdirs, files in os.walk(os.path.join(sys.path[0],username)): 
        for filename in files:
            email_index += 1    
            # untuple header data
            src, dt, title = read_email_header(os.path.join(username,filename))
            # resize table headers if needed to match each string
            index_len += int( (index_len < len(str(email_index))) * (len(str(email_index)) - index_len) )
            from_len += int( (from_len < len(src)) * (len(src) - from_len) )
            dt_len += int( (dt_len < len(str(dt))) * (len(str(dt)) - dt_len) )
            title_len += int( (title_len < len(title)) * (len(title) - title_len) )

            # if the array is empty, just append this item
            if len(inbox) == 0:
                inbox.append((src,dt,title))
            else:
                # Binary-sort and place the item in the array;
                # initialize low and high pointers
                lowi = 0
                low = inbox[lowi][1]
                highi = len(inbox)-1
                high = inbox[highi][1]

                if dt > high:
                    inbox.append((src,dt,title))
                elif dt < low:
                    inbox = [(src,dt,title)] + inbox
                
                while (highi - lowi) > 1:
                    midi = int(round((lowi+highi)/2))
                    mid = inbox[midi][1]
                    
                    if mid <= dt:
                        lowi = midi
                        low = mid
                    if dt <= mid:
                        highi = midi
                        high = mid
                if (lowi == highi) or ((low < dt) and (high > dt)):
                    insert_at(inbox,(src,dt,title),highi)
                elif dt < low:
                    insert_at(inbox,(src,dt,title),lowi)
    # Create header string
    #            inbox length;    'Index' width    'From' width;   'DateTime' width;  'Title' width
    header = str(len(inbox))+";"+str(index_len)+";"+str(from_len)+";"+str(dt_len)+";"+str(title_len)
    user_inbox[username] = (header,list(reversed(inbox)))

# Walks the inbox directory of the current authenticated user, compiles a list of emails, and sends them to the client.
def view_inbox(username, cipher, connection):
    global user_inbox

    # reload the user inbox to check for new emails
    cache_inbox(username)

    # initialize pointers to inbox and header of the current user
    inbox = user_inbox[username][1]
    header = user_inbox[username][0]

    # Send encrypted header data
    enc_header = cipher.encrypt(pad(header.encode('ascii'), 16))
    connection.send(enc_header)
    # block until confirmation from client
    connection.recv(1)

    # Encrypt and send each table item
    inbox_len = len(inbox)
    for i in range(inbox_len):
        src,dt,title = inbox[i]
        #       email index;  source;  datetime;  title 
        datastr = str(i+1)+";"+src+";"+str(dt)+";"+title
        enc_datastr = cipher.encrypt(pad(datastr.encode('ascii'), 16))
        connection.send(enc_datastr)
        # block until confirmation from client
        connection.recv(1)

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
                        view_inbox(username, cipher, connectionSocket)
                    #Viewing Email Subprotocol
                    elif (int(choice) == 3):
                        #recieve index
                        encryptedIndex = connectionSocket.recv(2048)
                        index = unpad(cipher.decrypt(encryptedIndex), 16).decode('ascii')

                        #get the file associated with the index
                        fullTitle = get_file(username,index)
                        userPath = sys.path[0] + "/" + username
            
                        #open the file to read, get the size and send it to the client
                        with open(os.path.join(userPath, fullTitle),"r") as f:
                        viewFile = f.read()
                        sizeOfFile = str(len(viewFile))
                        encryptedMessage = cipher.encrypt(pad(sizeOfFile.encode('ascii'), 16))
                        connectionSocket.send(encryptedMessage)
                
                        #recieves the okay to send file (dummy recv)
                        decryptedMessage = connectionSocket.recv(2048)
                        message = unpad(cipher.decrypt(encrypted_menu), 16).decode('ascii')

                        #Send file
                        encryptedMessage = cipher.encrypt(pad(viewFile.encode('ascii'), 16))
                        connectionSocket.send(encryptedMessage)
                        
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
