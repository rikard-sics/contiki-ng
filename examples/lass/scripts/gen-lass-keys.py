import os
import csv
from pycoin.encoding import hexbytes
from pycoin.ecdsa.Point import Point as ecc_point
from pycoin.ecdsa import secp256r1 as p256
from pycoin.encoding import sec, hexbytes
from pycoin.satoshi import der
from secrets import randbelow
from hashlib import sha256


class simple_pki():

    def __init__(self):
        self.keys = {}
        print("Starting PKI")
        #id, public key, private key
        f = open('../key-pairs.csv', 'r')
        for row in csv.reader(f, delimiter=','):
            pk_bytes = bytes.fromhex(row[1])
            sk = int(row[2], 16)
            pub = sec.sec_to_public_pair(pk_bytes, generator=p256.secp256r1_generator)
            self.keys[int(row[0])] = (pub, sk)


    #return pk as a point object
    def get_pk(self, index):
        pk = self.keys[index][0]
        return ecc_point(pk[0], pk[1], p256.secp256r1_generator)


    def get_pk_bytes(self, index):
        pubKey = self.keys[index][0]
        pk_bytes = sec.public_pair_to_sec(pubKey, compressed=False)
        return pk_bytes


def nike(id1, id2, their_pk, my_sk):
   # print("Nike ID1 {} ID2 {}:".format(id1, id2))
    shared_secret = their_pk*my_sk
    shared_secret = sec.public_pair_to_sec(shared_secret, compressed=False)
    shared_secret = shared_secret[1:]

    data = id1.to_bytes(2, byteorder='big')
    data += id2.to_bytes(2, byteorder='big')
    data += shared_secret
    symmetric_key = sha256(data).digest()
    #print("{}".format(sha256(data).hexdigest())) 
    return symmetric_key


pki = simple_pki()
generator = p256.secp256r1_generator
sk_iot = 0x7e0016170db75d19d055912415f5aca6431b2fadcea5c5949007332015191654
pk_iot = generator*sk_iot


with open('lass-keys.c.temp', 'w') as f:
    f.write('#include "lass-crypto.h"\n\n')
    f.write('const uint8_t lass_keys[LASS_KEY_LEN_BYTES] = {\n')
    for i in range(2,10002):
             
        pub_key = pki.get_pk(i)
        symmetric_key = nike(1, i, pub_key, sk_iot)
        symmetric_key = symmetric_key[:16]
        for i in range(len(symmetric_key)):
            f.write("0x{:02x}, ".format(symmetric_key[i]))
        
        f.write("\n")

    f.write("};")
