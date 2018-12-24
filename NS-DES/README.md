HOW TO EXECUTE PROPERLY
----------------------------------------
Note: You will need to import des.py from the DES folder into the same directory

1. Run python ns-kdc.py
2. Run python ns-bob.py first
3. Run python ns-alice.py second

Needham-Schroeder will not work if Alice attempts to make an invalid
connection. Bob must log in first for the program to work.

BOB V.S. ALICE
----------------------------------------
Bob: Passive listener. Establishes itself w/ KDC and waits for input from
Alice.
Alice: Active client. Establishes itself w/ KDC and sends Bob the info
needed to setup a session between the two of them.

COMPUTATIONAL DIFFIE-HELLMAN
----------------------------------------
I performed Diffie-Hellman as specified in the class notes. I created a
prime q (hard-coded b/c I didn't want to start randomly generating primes)
and a hard-coded alpha value. I pass those values along with the client's
public key to the KDC, which generates its own public key and sends it to 
the client. At this point, both the KDC and client have the public keys,
and it just requires them to do modular exponentation with them.

The exact way I did it can be observed best in generate_shared_key() in 
ns-kdc.py. Most of the code is self-explanatory, but I added in a pretty
weird format_key() function. The purpose of this function was just to
pad the randomized value that came out of Diffie-Hellman so that it ended
up being 64 bits. No real mathematics went into the thought of this, I
just xor the value with a constant and take the first 8 bytes.

Also, while Alice and Bob do the same things for Diffie-Hellman, the server
treats them differently. The server just sends Bob its generated public key,
while Alice receives enough information to set up a session between her and
Bob.

NEEDHAM-SCHROEDER PROTOCOL
----------------------------------------
For Needham-Schroeder, I followed these general steps:
1. Alice and Bob establish a master key w/ the KDC with Diffie-Hellman
2. Alice sends a request to the KDC asking for a session key
3. KDC responds back with encrypted message (Alice key) of new session key,
   timestamp, and a ticket, which is another encrypted message (Bob key) of
   the new session key.
4. Alice decrypts response, extracts session key, ticket, and timestamp.
5. Checks if timestamp is valid.
6. Sends ticket to Bob (she can't decrypt it as no Bob master key) with
   another timestamp.
7. Bob checks if timestamp is valid.
8. Bob decrypts session key from ticket.
9. Sends a nonce to Alice encrypted w/ new session key.
10. Alice responds w/ f(nonce) - for me, f() was just multiplying the
    nonce by 2. Function could be made harder upon request.
11. Bob decrypts Alice response w/ session key, ensures response is the
    f(nonce) agreed upon by both parties.
12. Authentication successful. This is where you can start communication.
    (I didn't implement that, however...)

I protected myself from replay attacks by using Denning AS, or just adding
a timestamp onto certain packages. This ensures that the attacker must
perform the replay attack within a certain period (I've set mine to 1 hour)
in order to make it work. Otherwise, the request will be rejected as it's
an illegal timestamp.

*Note, a nonce was included as well, but I believe that's just used to
randomize the encryption.
