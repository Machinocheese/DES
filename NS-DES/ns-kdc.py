import des
import socket
import random
import sys
import time

xor_64bit = 0xcf1dde0ca106cebc #artificially inflates key to 64bit
key_database = {} #global database to store {addr:key}

def format_key(shared_key): #inflates key to 64bits
    return int(format((shared_key ** 3) ^ xor_64bit, 'x')[0:16], 16)

#responds to Alice
def generate_shared_key(q, alpha, pub_key, address):
    global key_database
    secret_key = random.randint(0, q)
    return_key = pow(alpha, secret_key, q) #pass this to client
    shared_key = pow(pub_key, secret_key, q)
    shared_key = format_key(shared_key) #store this as client master key
    key_database[address] = shared_key
    return [return_key, shared_key]

#responds to Alice
def generate_encrypted_response(key_party, nonce, party2_id):
    if party2_id not in key_database:
        print "Error: " + party2_id + " not in key_database"
        return
    party2_key  = key_database[party2_id] #bob key stored in database
    session_key = random.getrandbits(64) #session key for alice-bob
    ticket      = des.des_api(str(session_key), str(party2_key), True) #encrypted ticket meant for bob to get session key
    timestamp   = str(int(time.time())) #beat replay attacks
    message     = str(session_key) + "||" + nonce + "||" + ticket + "||" + timestamp
    message = des.des_api(str(message), str(key_party), True)
    return message

def listen():
    global key_database
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    connection.bind(('0.0.0.0', 9090))
    connection.listen(64)

    while True:
        current_connection, address = connection.accept()        
    
        data  = current_connection.recv(128).split("||")
        value = generate_shared_key(int(data[0]), int(data[1]), int(data[2]), str(address))
        if len(data) == 5: #alice case (active client)
            message = generate_encrypted_response(value[1], data[3], data[4])
            if not message:
                continue
            current_connection.send(str(value[0]) + "||" + message)
        else: #bob case (passive listener client)
            current_connection.send(str(value[0]) + "||" + data[3])
        print "New key from " + str(address) + ": " + format(value[1], 'x')
            
if __name__ == "__main__":
    listen()
