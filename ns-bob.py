import des
import sys
import socket
import os
import random
import time

xor_64bit = 0xcf1dde0ca106cebc
q =     6725021
alpha = 17
invalid_time = 3600 #expiration 

def format_key(shared_key):
    return int(format((shared_key ** 3) ^ xor_64bit, 'x')[0:16], 16)

def connect_kdc():
    nonce = os.urandom(64)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('localhost', 9191)) #contact Bob @ localhost 9191
    sock.connect(('localhost', 9090)) #contact KDC @ localhost 9090
    try:
        secret_key = random.randint(0, q)
        pub_key = pow(alpha, secret_key, q)
        sock.sendall(str(q) + "||" + str(alpha) + "||" + str(pub_key) + "||" + nonce)

        data = sock.recv(128).split("||")
        pub_key2 = int(data[0])
    
        shared_key = pow(pub_key2, secret_key, q)
        shared_key = format_key(shared_key)
        
        new_nonce = data[1]
        if new_nonce != nonce:
            print "Invalid response"
            return

        return shared_key
        
    finally:
        print 'closing socket'
        sock.close()

#wait for Alice to initiate communication
def listen(shared_key):
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    connection.bind(('0.0.0.0', 9191))
    connection.listen(64)

    current_connection, address = connection.accept()
    data = current_connection.recv(64).split("||") 
    data_key = data[0] #DES-encrypted session key
    decrypted = des.des_api(data_key, str(shared_key), False)

    #timestamp expiration
    if time.time() - int(data[1]) > invalid_time:
        print "Invalid Request"
        return

    original = random.randint(0, 10000) #generate nonce
    nonce = des.des_api(str(original), str(decrypted), True)
    current_connection.send(nonce)
    
    current_connection, address = connection.accept()
    new_nonce = current_connection.recv(16)
    new_nonce = des.des_api(new_nonce, str(decrypted), False)
    print new_nonce
    if int(new_nonce) == 2 * original: #affirm f(nonce) is correct
        print "Authentication success!"
        #do what you want after authentication...
    else:
        print "Authentication Failure. Shutting down..."
        return

#Alice is the client that contacts the KDC for a session key
#for communication between two parties.
if __name__ == "__main__":
    
    shared_key = connect_kdc()
    listen(shared_key)

