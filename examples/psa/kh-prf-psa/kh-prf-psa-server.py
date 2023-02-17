import datetime
import logging

import asyncio

import aiocoap.resource as resource
import aiocoap

from pycoin.ecdsa.Point import Point as ecc_point
from pycoin.ecdsa import secp256r1 as p256
from pycoin.encoding import sec, hexbytes
from pycoin.satoshi import der
from secrets import randbelow
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util import Counter
import hashlib
import csv

class simple_pki():

    def __init__(self):
        self.keys = {}
        print("Starting PKI")
        #id, public key, private key
        f = open('key-pairs.csv', 'r')
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

key = None
pki = simple_pki()


# logging setup
logging.basicConfig(level=logging.INFO)
logging.getLogger("coap-server").setLevel(logging.DEBUG)

def print_like_iot(two_points):
    two_points = sec.public_pair_to_sec(pubKey, compressed=False)
    two_points = hexbytes.b2h(two_points[1:]) # strip first 0x04 byte and convert to hex string
    #reverse endianness of x and y corrdinates
    print(len(two_points))
    x = "".join(reversed([two_points[i:i+2] for i in range(0, 64, 2)]))
    y = "".join(reversed([two_points[i:i+2] for i in range(64, 128, 2)]))

def nike(id1, id2, their_pk, my_sk):
    shared_secret = their_pk*my_sk
    shared_secret = sec.public_pair_to_sec(shared_secret, compressed=False)
    shared_secret = shared_secret[1:]
    
    data = id1.to_bytes(2, byteorder='big')
    data += id2.to_bytes(2, byteorder='big')
    data += shared_secret
    symmetric_key = sha256(data).digest()
    return symmetric_key



def psa_encrypt(psa_key, label, message, num_users):
    enc_sum = 0 
    for lamb in range(2096): # start small
        data = label.to_bytes(8, byteorder='big')
        data += b'\x00'
        lamb_1 = lamb + 1
        data += (lamb_1).to_bytes(2, byteorder='big')
        #print(hexbytes.b2h(data))
        s = hashlib.sha256()
        s.update(data)
        h = s.digest()
        hash_num = int.from_bytes(h[-16:], "big")
        
        tmp_sum = (hash_num*psa_key[lamb])%(2**128)
        enc_sum = (enc_sum + tmp_sum)%(2**128)

    message = message*num_users+1
    enc_sum = (enc_sum*(2**85))//(2**128)
    return (enc_sum+message)%(2**128)

        
def encrypt_psa_key_update(scratch_pad, symmetric_key):
    c = []
    crypto = AES.new(symmetric_key, AES.MODE_ECB)
    for i in range(len(scratch_pad)):
        counter = i.to_bytes(16, byteorder='big')
        ciphertext = crypto.encrypt(bytes(counter))
        num = int.from_bytes(ciphertext, "big") 
        
        scratch_pad[i] = (num+psa_key[i])%(2**128)
        

def import_key_file():
    print("reading PSA key from file")
    arr = []
    with open('key.txt', 'r') as f:
        for line in f:
            arr.append(int(line, 16))

    return arr


received_psa_key = []


class BlockResource(resource.Resource):
    """Example resource which supports the GET and PUT methods. It sends large
    responses, which trigger blockwise transfer."""

    def __init__(self):
        super().__init__()

        self.set_content(key)

    def set_content(self, content):
        self.content = content

    async def render_get(self, request):
        print("Requested Public-Key ", int(request.opt.uri_query[0]))
        i = int(request.opt.uri_query[0])
        pubKey = pki.get_pk_bytes(i)
        id_pubKey = i.to_bytes(2, byteorder='big') 
        id_pubKey += pubKey
        self.set_content(id_pubKey)
        print('id+bubkey', id_pubKey)
        return aiocoap.Message(payload=self.content)

    async def render_put(self, request):
        self.set_content(request.payload)
        return aiocoap.Message(code=aiocoap.CHANGED, payload=self.content)

class DataResource(resource.Resource):
    """Example resource which supports the GET and PUT methods. It sends large
    responses, which trigger blockwise transfer."""

    def __init__(self):
        super().__init__()

        self.set_content(key)

    def set_content(self, content):
        self.content = b''

    async def render_put(self, request):
        print("PUT! got message {}".format(request.payload))
        #TODO aggregate data!
        return aiocoap.Message(code=aiocoap.CHANGED, payload=self.content)

class KeyResource(resource.Resource):
    """Example resource which supports the GET and PUT methods. It sends large
    responses, which trigger blockwise transfer."""

    def __init__(self):
        super().__init__()
        self.content = b''

    def set_content(self, content):
        self.content = b''

    async def render_put(self, request):
        print("message len {}".format(len(request.payload)))
        #TODO aggregate data!
        received_psa_key.append(request.payload)
        return aiocoap.Message(code=aiocoap.CHANGED, payload=self.content)


async def main():

    # Resource tree creation
    root = resource.Site()

    root.add_resource(['.well-known', 'core'],
            resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(['pubkey'], BlockResource())
    root.add_resource(['key'], KeyResource())
    root.add_resource(['data'], DataResource())
    #root.add_resource(['whoami'], WhoAmI())

    await aiocoap.Context.create_server_context(root)

    # Run forever
    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    asyncio.run(main())
