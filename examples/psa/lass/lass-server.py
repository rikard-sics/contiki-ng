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


def nike(id1, id2, their_pk, my_sk):
    shared_secret = their_pk*my_sk
    shared_secret = sec.public_pair_to_sec(shared_secret, compressed=False)
    shared_secret = shared_secret[1:]
    
    data = id1.to_bytes(2, byteorder='big')
    data += id2.to_bytes(2, byteorder='big')
    data += shared_secret
    symmetric_key = sha256(data).digest()
    return symmetric_key



def lass_encrypt(lass_keys, label, message, num_users):
    print("psa encrypt")
    enc_sum = message 
    for i in range(num_users): # start small
        print("key: ",hexbytes.b2h(lass_keys[i]))
        crypto = AES.new(lass_keys[i], AES.MODE_ECB)
        counter = label.to_bytes(16, byteorder='big')
        print("ctr:", hexbytes.b2h(counter))
        ciphertext = crypto.encrypt(bytes(counter))
        new_num = int.from_bytes(ciphertext, "big")
        print(new_num)
        enc_sum = (enc_sum+new_num)%(2**128)

    return enc_sum


generator = p256.secp256r1_generator

#compute public key because i have not found a way to import a key in hex format
sk_iot = 0x7e0016170db75d19d055912415f5aca6431b2fadcea5c5949007332015191654
pk_iot = generator*sk_iot

lass_keys = []

for id_j in range(2,1002):
    pub_key = pki.get_pk(id_j)
    pbb = pki.get_pk_bytes(id_j)
    symmetric_key = nike(1, id_j, pub_key, sk_iot)
    symmetric_key = symmetric_key[:16]
    print("nike {} key {}".format(id_j, hexbytes.b2h(symmetric_key)))
    lass_keys.append(symmetric_key) 


c = lass_encrypt(lass_keys, 1, 0, 10)
print("ciphertext", hex(c))

print("done")
class blockresource(resource.Resource):
    """example resource which supports the get and put methods. it sends large
    responses, which trigger blockwise transfer."""

    def __init__(self):
        super().__init__()

        self.set_content(key)

    def set_content(self, content):
        self.content = content

    async def render_get(self, request):
        print("requested public-key ", int(request.opt.uri_query[0]))
        i = int(request.opt.uri_query[0])
        pubkey = pki.get_pk_bytes(i)
        id_pubkey = i.to_bytes(2, byteorder='big') 
        id_pubkey += pubkey
        self.set_content(id_pubkey)
        return aiocoap.Message(payload=self.content)

    async def render_put(self, request):
        self.set_content(request.payload)
        return aiocoap.Message(code=aiocoap.changed, payload=self.content)

class dataresource(resource.Resource):

    def __init__(self):
        super().__init__()
        self.set_content(key)

    def set_content(self, content):
        self.content = b''

    async def render_put(self, request):
        return aiocoap.Message(code=aiocoap.changed, payload=self.content)

async def main():

    # resource tree creation
    root = resource.Site()

    root.add_resource(['.well-known', 'core'],
            resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(['pubkey'], blockresource())
    root.add_resource(['data'], dataresource())
    #root.add_resource(['whoami'], WhoAmI())

    await aiocoap.Context.create_server_context(root)

    # Run forever
    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    asyncio.run(main())

