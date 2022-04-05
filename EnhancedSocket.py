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

# Socket enhancement wrapper over an active socket connection. 
class EnhancedSocket:

    # Initializes authentication, encryption, and integrity hashing to secure the provided socket.
    #   connectionSocket: An insecure socket connection which implements send() and recv() 
    #   key: The filepath to the .pem key file used for this connection.
    def __init__(self,key,connectionSocket):
        self.sock = connectionSocket