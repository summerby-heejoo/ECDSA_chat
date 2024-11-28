import socket
import random
from threading import Thread
from datetime import datetime
from colorama import Fore, init, Back
from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
from random import randint
import math
import Crypto
from Crypto.Cipher import AES
from Crypto.Hash import SHA256 as SHA
from base64 import b64encode
import base64
# 이게 멀쩡한 것

pubkeys = {}

# init colors
init()

# set the available colors
colors = [Fore.BLUE, Fore.CYAN, Fore.GREEN, Fore.LIGHTBLACK_EX,
          Fore.LIGHTBLUE_EX, Fore.LIGHTCYAN_EX, Fore.LIGHTGREEN_EX,
          Fore.LIGHTMAGENTA_EX, Fore.LIGHTRED_EX, Fore.LIGHTWHITE_EX,
          Fore.LIGHTYELLOW_EX, Fore.MAGENTA, Fore.RED, Fore.WHITE, Fore.YELLOW
          ]

# choose a random color for the client
client_color = random.choice(colors)

# server's IP address
# if the server is not on this machine,
# put the private (network) IP address (e.g 192.168.1.2)
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5002  # server's port
separator_token = "<SEP>"  # we will use this to separate the client name & message

# initialize TCP socket
s = socket.socket()
print(f"[*] Connecting to {SERVER_HOST}:{SERVER_PORT}...")
# connect to the server
s.connect((SERVER_HOST, SERVER_PORT))
print("[+] Connected.")
# prompt the client for a name
name = input("Enter your name: ")

cv = Curve.get_curve('secp256k1')
pv_key = ECPrivateKey(randint(0, 2 ** 256), cv)
pu_key = pv_key.get_public_key()
users = set()
signer = ECDSA()
dhkey = {}
dec_msg = ''
processed_clients = set()
threads = []

def listen_for_messages():
    while True:
        try:
            message = s.recv(1024).decode()

        except Exception as e:
            # client no longer connected
            # remove it from the set
            print("end program!!")
            s.close()
            return
        else:
            get_pubkeys(message)


def gen_key(key):
    pp = pubkeys[key].split(' ')
    dhkey[key] = str((pv_key.d * Point(int(pp[3], 16), int(pp[6], 16), cv)).x)
    print(dhkey)


def get_pubkeys(message):
    if message.find('ECPublicKey') > 0:
        data = message.split(separator_token)
        pubkeys[data[0]] = data[1]
        # dec_msg = myAES.decrypt(dhkey[data[0]], 'initvalue', 128)
        # your_pu_key = message.join(message.slice[1:])
        for user in pubkeys.keys():
            users.add(user)
            if user != name:
                gen_key(user)

        print("yours", users)
    else:
        # message = message.replace(separator_token, ": ")
        data = message.split(' ')
        # user = data[1].replace(':', '')
        for user in users:
            if user != name and user not in processed_clients:
                dec_msg = myAES(dhkey[user], 'initvalue', 128)
                msg = dec_msg.decrypt(data[2])
                outmsg = f"{data[0]} {data[1]} {str(msg, 'utf-8')} {Fore.RESET}"
                print(outmsg)

        clients_to_send = [user for user in users if user != name]
        for client in clients_to_send:
            thread = threading.Thread(target=send_message, args=(client,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()


#
#     # point = cv.encode_point(pu_key.W, compressed=True)
#     return pu_key


# def gen_DH(pv_key, your_pu_key):
#     print(type(pv_key), type(your_pu_key), your_pu_key.W)
#     return pv_key * your_pu_key.P

class myAES():
    # Class generator
    # keysize = 128, 192, 256
    def __init__(self, keytext, ivtext, keysize):
        hash_fn = SHA.new()
        hash_fn.update(keytext.encode('utf-8'))
        key = hash_fn.digest()
        keylen = int(keysize / 8)
        self.key = key[:keylen]
        hash_fn.update(ivtext.encode('utf-8'))
        iv = hash_fn.digest()
        self.iv = iv[:16]

        # 메소드 1: 메세지 채움

    def makeEnabled(self, plaintext):
        # 작성 부분 1
        length = 16 - (len(plaintext) % 16)
        plaintext += chr(length) * length
        return plaintext

    # 메소드 2: 메세지 암호화
    def encrypt(self, plaintext):
        plaintext = self.makeEnabled(plaintext)
        # key, CBC 모드와 iv를 인자로 AES의 객체를 생성함
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        # AES 암호화
        # 작성 부분 2
        encmsg = aes.encrypt(plaintext.encode('utf-8'))
        return b64encode(encmsg).decode('utf-8')

    # 메소드 3: 복호화 메세지 후처리
    def postDec(self, dec_msg):
        # 작성 부분 3
        pad = int(dec_msg[-1])
        dec_msg = dec_msg[:-pad]

        return dec_msg

    # 메소드 4: 암호문 복호화
    def decrypt(self, ciphertext):
        # AES 객체 생성, ciphertext 복호화
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        ciphertext = base64.b64decode(ciphertext)
        dec_msg = aes.decrypt(ciphertext)

        return self.postDec(dec_msg)


def main():
    cryptotalk = False
    while True:
        # input message we want to send to the server
        to_send = input()

        # else:
        # sig = signer.sign_k(message, pv_key)
        # assert (signer.verify(message, sig, pu_key))
        # a way to exit the program
        # if to_send.lower() == 'dh':
        #     for key in pubkeys.keys():
        #         if key != name:
        #             # pp = pubkeys['alice'].strip('/\n')
        #             #pp = pubkeys[key].split(' ')
        #             # print(pp)
        #             # print(pp[3].strip('\n'))
        #             # print(pp[6])
        #             #dhkey = pv_key.d * Point(int(pp[3], 16), int(pp[6], 16), cv)
        #             print(dhkey)
        #             cryptotalk = True

        if to_send.lower() == 'q':
            to_send = f"{name}{separator_token}q"
            # finally, send the message
            s.send(to_send.encode())

            return

        else:
            # if cryptotalk == True:
            for user in users:
                if user != name:
                    myaes = myAES(dhkey[user], 'initvalue', 128)
                    msg = myaes.encrypt(to_send)
                    # add the datetime, name & the color of the sender
                    # date_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    msg = f"{client_color} {name}{separator_token}{msg} {Fore.RESET}"
                    # finally, send the message
                    s.send(msg.encode())


if __name__ == '__main__':
    # make a thread that listens for messages to this client & print them
    t = Thread(target=listen_for_messages)
    # make the thread daemon so it ends whenever the main thread ends
    t.daemon = True
    # start the thread
    t.start()

    to_send = pu_key
    to_send = f"{name}{separator_token}{to_send}"
    # finally, send the message
    s.send(to_send.encode())

    main()
    # close the socket
    s.close()
