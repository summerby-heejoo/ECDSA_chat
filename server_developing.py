import socket
from threading import Thread
from typing import Set, Any
from ecpy.curves import Curve, Point
from ecpy.keys import ECPrivateKey, ECPublicKey
from random import randint
import time

pubkeys = {}
cv = Curve.get_curve('secp256k1')
pv_key = ECPrivateKey(randint(0, 2 ** 256), cv)

# server's IP address
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5002  # port we want to use
separator_token = "<SEP>"  # we will use this to separate the client name & message

# initialize list/set of all connected client's sockets
client_sockets: set[Any] = set()
# create a TCP socket
s = socket.socket()
# make the port as reusable port
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# bind the socket to the address we specified
s.bind((SERVER_HOST, SERVER_PORT))
# listen for upcoming connections
s.listen(5)
print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")
users = set()

def listen_for_client(cs):
    """
    This function keep listening for a message from `cs` socket
    Whenever a message is received, broadcast it to all other connected clients
    """
    while True:
        try:
            # keep listening for a message from `cs` socket
            msg = cs.recv(1024).decode()

        except Exception as e:
            # client no longer connected
            # remove it from the set
            print(f"[!] Error: {e}")
            # user.remove(data[0])
            # del pubkeys[data[0]]
            # if len(users) == 0:
            #     print("no users!!")
            # else:
            #     print("users", users)
            client_sockets.remove(cs)
            cs.close()
            return
        else:
            # if we received a message, replace the <SEP>
            # token with ": " for nice printing
            data = msg.split(separator_token)
            # print(msg)
            if len(data) > 1 and data[1] == 'q':
                user.remove(data[0])
                del pubkeys[data[0]]
                if len(users) == 0:
                    print("no users!!")
                else:
                    print("users", users)
                client_sockets.remove(cs)
                cs.close()
                return
            else:
                # print(msg)
                get_pubkeys(msg)
                # print("user", user)
        # iterate over all connected sockets


def get_pubkeys(message):
    if message.find('ECPublicKey') > 0:
        data = message.split(separator_token)
        pubkeys[data[0]] = data[1]
        # your_pu_key = message.join(message.slice[1:])
        # print("users", pubkeys)
        # pp = data[1].split(' ')
        # print(pp)
        # print(pp[3].strip('\n'))
        # print(pp[6])
        # # dhkey = Point(int(pp[3],16), int(pp[6], 16), cv)
        # dhkey = pv_key.d * Point(int(pp[3], 16), int(pp[6], 16), cv)
        # print(dhkey)

        for name, user in pubkeys.items():
            #print(name)
            #if user != name:
            to_send = f"{name}{separator_token}{user}"

            for client_socket in client_sockets:
                client_socket.send(to_send.encode())
                time.sleep(0.1)

        for user in pubkeys.keys():
            users.add(user)
        print("users", users)

    else:
        message = message.replace(separator_token, ": ")
        print(message)
        for client_socket in client_sockets:
            #and send the message
            client_socket.send(message.encode())


def main():
    while True:
        # we keep listening for new connections all the time
        client_socket, client_address = s.accept()
        print(f"[+] {client_address} connected.")
        # add the new connected client to connected sockets
        client_sockets.add(client_socket)
        # start a new thread that listens for each client's messages
        t = Thread(target=listen_for_client, args=(client_socket,))
        # make the thread daemon so it ends whenever the main thread ends
        t.daemon = True
        # start the thread
        t.start()


if __name__ == '__main__':
    main()
    # close client sockets
    for cs in client_sockets:
        cs.close()
    # close server socket
    s.close()
