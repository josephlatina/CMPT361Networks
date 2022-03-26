# Group Member Names: Joseph Latina, Andrew, Raphelos
# CMPT361 Project - Secure Mail Transfer Protocol
#Purpose: generate keys for server and client

import os
import sys
from Crypto.PublicKey import RSA


#Generate server private and public keys
server_key = RSA.generate(2048)
server_private_key = server_key.export_key("PEM")
server_public_key = server_key.publickey().export_key("PEM")

#Save server keys as PEM
with open(os.path.join(sys.path[0], "server", "server_public.pem"), "wb+") as f:
    f.write(server_public_key)
with open(os.path.join(sys.path[0], "server", "server_private.pem"), "wb+") as f:
    f.write(server_private_key)


#Generate client private and public keys
client_key = RSA.generate(2048)
client_private_key = client_key.export_key("PEM")
client_public_key = client_key.publickey().export_key("PEM")

#Save server keys as PEM
with open(os.path.join(sys.path[0], "client", "client_public.pem"), "wb+") as f:
    f.write(client_public_key)
with open(os.path.join(sys.path[0], "client", "client_private.pem"), "wb+") as f:
    f.write(client_private_key)

