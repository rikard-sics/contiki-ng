import datetime
import logging

import asyncio

import aiocoap.resource as resource
import aiocoap

from pycoin.ecdsa import secp256r1 as p256
from pycoin.encoding import sec, hexbytes
from pycoin.satoshi import der
from secrets import randbelow
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util import Counter
import hashlib

key = None

class BlockResource(resource.Resource):
    """Example resource which supports the GET and PUT methods. It sends large
    responses, which trigger blockwise transfer."""

    def __init__(self):
        super().__init__()
        self.set_content(key)

    def set_content(self, content):
        self.content = content

    async def render_get(self, request):
        return aiocoap.Message(payload=self.content)

    async def render_put(self, request):
        print('PUT payload: %s' % request.payload)
        self.set_content(request.payload)
        return aiocoap.Message(code=aiocoap.CHANGED, payload=self.content)




class WhoAmI(resource.Resource):
    async def render_get(self, request):
        text = ["Used protocol: %s." % request.remote.scheme]

        text.append("Request came from %s." % request.remote.hostinfo)
        text.append("The server address used %s." % request.remote.hostinfo_local)

        claims = list(request.remote.authenticated_claims)
        if claims:
            text.append("Authenticated claims of the client: %s." % ", ".join(repr(c) for c in claims))
        else:
            text.append("No claims authenticated.")

        return aiocoap.Message(content_format=0,
                payload="\n".join(text).encode('utf8'))

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
    print("two points {}{}".format(x,y))

def nike(id1, id2, their_pk, my_sk):
    print("nike")
    shared_secret = their_pk*my_sk
    shared_secret = sec.public_pair_to_sec(shared_secret, compressed=False)
    shared_secret = shared_secret[1:]
    
    data = id1.to_bytes(2, byteorder='big')
    data += id2.to_bytes(2, byteorder='big')
    data += shared_secret
    symmetric_key = sha256(data).digest()
    return symmetric_key



def psa_encrypt(psa_key, label, message):
    print("psa encrypt")
    
    for lamb in range(1): # start small
        data = label.to_bytes(8, byteorder='big')
        data += b'\x00'
        data += lamb.to_bytes(2, byteorder='big')
        print(hexbytes.b2h(data))
        s = hashlib.sha3_512()
        s.update(data)
        h = s.digest()
        i = int.from_bytes(h[-16:], "big")
        print("hash: ", hexbytes.b2h(h))
        print("int: ", i)


        
def generate_keystream(psa_key, symmetric_key, length):
    c = []
    crypto = AES.new(symmetric_key, AES.MODE_ECB)
    for i in range(10):
        counter = i.to_bytes(16, byteorder='big')
        #print("ctr: ",hexbytes.b2h(counter))
        ciphertext = crypto.encrypt(bytes(counter))
        #print("{} ciphertext {}".format(i,hexbytes.b2h(ciphertext)))
        num = int.from_bytes(ciphertext, "big") 
        #print("interpreted as: ", num)
        c.append((num+psa_key[i])%(2**128))
        c.append("Adding: {} + {} = {}".format(psa_key[i], num, (num+psa_key[i])%(2**128)))
    return c

def import_key_file():
    print("reading PSA key from file")
    arr = []
    with open('key.txt', 'r') as f:
        for line in f:
            arr.append(int(line, 16))

    return arr


generator = p256.secp256r1_generator
privKey = 0xbd8092a09fab6910483fe6d9baacf77c59532daad8fc1b7c35c806acf7909bed
#privKey = randbelow(generator.order())
pubKey = generator * privKey
sec_pub = sec.public_pair_to_sec(pubKey, compressed=False)
print("priv: ", hex(privKey))
print("pub: ", hexbytes.b2h(sec_pub))
key = sec_pub


#compute public key because I have not found a way to import a key in hex format
sk = 0x7E0016170DB75D19D055912415F5ACA6431B2FADCEA5C5949007332015191654
pk_iot = generator*sk


symmetric_key = nike(1, 55555, pk_iot, privKey)

psa_key = import_key_file()
ciphertext = generate_keystream(psa_key, symmetric_key, 100)
print("ciphertext: ")
for i in ciphertext:
    print(i)

psa_encrypt(None, 12, 0)

async def main():

    # Resource tree creation
    root = resource.Site()

    root.add_resource(['.well-known', 'core'],
            resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(['other', 'block'], BlockResource())
    root.add_resource(['whoami'], WhoAmI())

    await aiocoap.Context.create_server_context(root)

    # Run forever
    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    asyncio.run(main())
