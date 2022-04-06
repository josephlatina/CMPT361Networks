# Group Member Names: Joseph Latina, Andrew Numrich, Raphael Wong
# CMPT361 Project - Secure Mail Transfer Protocol

import json
import socket
import os, glob, datetime
from datetime import datetime
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
sys.path.append("../")
from EnhancedSocket import EnhancedSocket, EnhancedClient, EnhancedServer

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
    dt = datetime.strptime(dtstr, "%Y-%m-%d %H:%M:%S.%f")
    return (srcusr,dt,title)

# Get a filename by an email's index in the user's inbox
def get_file(username,index):
    global user_inbox
    
    # load the user's inbox data if it isnt loaded yet
    if not username in user_inbox:
        cache_inbox(username)
    
    # get pointers to inbox and the email at the desired index 
    inbox = user_inbox[username][1]
    src,dt,title = inbox[int(index)-1]

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
def view_inbox(username, sock):
    global user_inbox

    # reload the user inbox to check for new emails
    cache_inbox(username)

    # initialize pointers to inbox and header of the current user
    inbox = user_inbox[username][1]
    header = user_inbox[username][0]

    # Send encrypted header data
    sock.send(header.encode('ascii'))
    # block until confirmation from client
    sock.recv(1)

    # Encrypt and send each table item
    inbox_len = len(inbox)
    for i in range(inbox_len):
        src,dt,title = inbox[i]
        #       email index;  source;  datetime;  title 
        datastr = str(i+1)+";"+src+";"+str(dt)+";"+title
        sock.send(datastr.encode('ascii'))
        # block until confirmation from client
        sock.recv(1)

def client_handle(sock):
    #Create 5 directory inboxes for the 5 clients, skips this step if they already exists
    if not os.path.exists("client1"):
        os.mkdir("client1")
        os.mkdir("client2")
        os.mkdir("client3")
        os.mkdir("client4")
        os.mkdir("client5") 
    
    # Send menu
    menu = "Select the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\n\n\tchoice: "
    sock.send(menu.encode('ascii')) 
    #Receive client choice
    choice = sock.recv(2048).decode('ascii') 

    #Perform the associated subprotocol
    while (int(choice) != 4):
        #Sending Email Subprotocol
        if (int(choice) == 1):
            response = sock.recv(2048).decode('ascii') 
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
            sock.send("ok".encode('ascii'))
            #Logic for safely recieving content message that may exceed 2048 bytes from client
            content = ""
            while contentLength > 0:
                if contentLength > 2048:
                    response = sock.recv(2048).decode('ascii')
                    content += response
                    contentLength -= 2048
                else:
                    response = sock.recv(2048).decode('ascii')
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
            view_inbox(username, sock)
        #Viewing Email Subprotocol
        elif (int(choice) == 3):
            #recieve index
            index = sock.recv(2048).decode('ascii')    
            #get the file associated with the index
            fullTitle = get_file(username,index)
            userPath = sys.path[0] + "/" + username

            #open the file to read, get the size and send it to the client
            with open(os.path.join(userPath, fullTitle),"r") as f:
                viewFile = f.read()
                sizeOfFile = str(len(viewFile))
                sock.send(sizeOfFile.encode('ascii'))

            #recieves the okay to send file (dummy recv)
            decryptedMessage = sock.recv(2048).decode('ascii')  
            #Send file
            sock.send(viewFile.encode('ascii'))

        #Receive client choice
        choice = sock.recv(2048).decode('ascii')
    #Connection Termination Subprotocol
    print("Terminating connection with " + username)
    sock.close()
    return

def server():
    srvr = EnhancedServer(5)
    srvr.listen(client_handle)

#----------
server()
