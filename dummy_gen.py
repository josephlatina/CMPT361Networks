# Group Member Names: Joseph Latina, Andrew, Raphelos
# CMPT361 Project - Secure Mail Transfer Protocol
#Purpose: Generate dummy mail in the server directory for debugging. 
import os
from datetime import date
# for each user
for i in range(5):
    # build name
    name = "client"+str(i+1)
    # build and create directory
    dir = "./server/"+name
    try:
        os.mkdir(dir)
    except:
        print("Directory already exists.")
    # create 3 messages per user
    for n in range(3):
        
        # build source username
        srcusr = "client"+str(5-i)

        # open and write to file:
        # (source username)_(title).txt
        f = open(dir+"/"+srcusr+"_"+"title"+str(n)+".txt","w")

        # make message source clientx where x = (5-i)  
        f.write(srcusr+'\n')
        
        # write a random time and date
        f.write(str(date(2020,4,19))+'\n')

        # make message destination for user 'i'
        f.write(name+'\n')
        
        # write title 
        f.write("This is a message "+str(n)+" for client "+str(i)+'\n')
        
        # build message
        msg = "This is the message content. Lorem ipsum whatever yeah. Have a good day "+name+"!"

        # write message length
        f.write(str(len(msg))+'\n')

        # write message content
        f.write(msg+'\n')

        # close stream
        f.close()



