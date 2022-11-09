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

plaintext = bytearray(100)

symmetric_key = nike(1, 55555, pk_iot, privKey)

IV = bytearray(16)
iv = int.from_bytes(IV, byteorder='big')
ctr = Counter.new(128, initial_value=iv)

crypto = AES.new(symmetric_key, AES.MODE_CTR, counter=ctr)
ciphertext = crypto.encrypt(bytes(plaintext))
print("ciphertext: ", hexbytes.b2h(ciphertext))

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
