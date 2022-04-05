# Group Member Names: Joseph Latina, Andrew, Raphelos
# CMPT361 Project - Secure Mail Transfer Protocol
#Purpose: generate keys for server and client

import os
import sys
from Crypto.PublicKey import RSA

#Create keys directory in client folder if it doesn't exist already
if (os.path.isdir("client/keys") == False):
    os.mkdir("client/keys")
#Create keys directory in server folder if it doesn't exist already
if (os.path.isdir("server/keys") == False):
    os.mkdir("server/keys")

#Generate server private and public keys
server_key = RSA.generate(2048)
server_private_key = server_key.export_key("PEM")
server_public_key = server_key.publickey().export_key("PEM")

#Save server keys as PEM
with open(os.path.join(sys.path[0], "server", "keys", "server_public.pem"), "wb+") as f:
    f.write(server_public_key)
with open(os.path.join(sys.path[0], "server","keys", "server_private.pem"), "wb+") as f:
    f.write(server_private_key)

#Generate and save client keys as PEM
for i in range(5):
    #generate client private and public keys
    client_key = RSA.generate(2048)
    client_private_key = client_key.export_key("PEM")
    client_public_key = client_key.publickey().export_key("PEM")

    #generate filename for files that will hold the keys
    public_filename = "client" + str(i+1) + "_public.pem"
    private_filename = "client" + str(i+1) + "_private.pem"

    #Save client public and private keys into client folder
    with open(os.path.join(sys.path[0], "client", "keys", public_filename), "wb+") as f:
        f.write(client_public_key)
    with open(os.path.join(sys.path[0], "client", "keys", private_filename), "wb+") as f:
        f.write(client_private_key)
    #Save client public key into server folder as well
    with open(os.path.join(sys.path[0], "server", "keys", public_filename), "wb+") as f:
        f.write(client_public_key)

#Save server public key into client folder as well
with open(os.path.join(sys.path[0], "client","keys", "server_public.pem"), "wb+") as f:
    f.write(server_public_key)
