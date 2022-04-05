# Group Member Names: Joseph Latina, Andrew, Raphelos
# CMPT361 Project - Secure Mail Transfer Protocol
#Purpose: Generate dummy mail in the server directory for debugging. 
import os
from datetime import datetime
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

        # build title
        title = "message about "+str(n)+" cats and "+str(i)+" dogs"

        # open and write to file:
        # (source username)_(title).txt
        f = open(dir+"/"+srcusr+"_"+title+".txt","w")

        # make message source clientx where x = (5-i)  
        f.write("From: "+srcusr+'\n')

        # make message destination for user 'i'
        f.write("To: "+name+'\n')

        # write a random time and date
        f.write("Time and Date Recieved: "+str(datetime(2020,4,19+n,6+i,n+i,n*i,int((n+1)/(i+1))))+'\n')

        # write title 
        f.write("Title: "+title+'\n')
        
        # build message
        msg = "This is the message content. Lorem ipsum whatever yeah. Have a good day "+name+"!"

        # write message length
        f.write("Content Length: "+str(len(msg))+'\n')

        # write message content
        f.write("Contents:\n"+msg)

        # close stream
        f.close()



