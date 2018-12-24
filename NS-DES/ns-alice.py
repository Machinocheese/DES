import des
import sys
import socket
import os
import random
import time

xor_64bit = 0xcf1dde0ca106cebc
q =     6725021
alpha = 17
bob = "('127.0.0.1', 9191)"
invalid_time = 3600 #expiration time of 1 hour for timestamp

def format_key(shared_key):
    return int(format((shared_key ** 3) ^ xor_64bit, 'x')[0:16], 16)

def connect_kdc():
    nonce = os.urandom(64)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 9090))
    try:
        secret_key = random.randint(0, q)
        pub_key = pow(alpha, secret_key, q)
        sock.sendall(str(q) + "||" + str(alpha) + "||" + str(pub_key) + "||" + nonce + "||" + bob)

        data = sock.recv(1024).split("||")
        pub_key2 = int(data[0])
    
        shared_key = pow(pub_key2, secret_key, q)
        shared_key = format_key(shared_key)
        
        message = des.des_api(data[1], str(shared_key), False).split("||")
        session_key = message[0]
        new_nonce = message[1]
        ticket    = message[2]
        given_time = int(message[3])

        #checks for invalid timestamp or invalid nonce
        if int(time.time()) - given_time > invalid_time or new_nonce != nonce:
            print "Invalid response"
            return
        
        return ticket, session_key
    finally:
        print 'closing socket'
        sock.close()

def connect_bob(ticket, session_key):
    timestamp = str(int(time.time()))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost',9191))
    sock.sendall(ticket + "||" + timestamp)

    nonce = sock.recv(16)
    nonce = des.des_api(nonce, str(session_key), False)

    nonce = des.des_api(str(int(nonce) * 2), str(session_key), True)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost',9191))
    sock.sendall(nonce)
    #Should be authenticated by here

if __name__ == "__main__":
    ticket, session_key = connect_kdc()
    connect_bob(ticket, session_key)
