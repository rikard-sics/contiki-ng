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

generator = p256.secp256r1_generator
privKey = randbelow(generator.order())
pubKey = generator * privKey
sec_pub = sec.public_pair_to_sec(pubKey, compressed=False)
print("pub: ", hexbytes.b2h(sec_pub))
print(type(sec_pub))
print(len(sec_pub))
key = sec_pub

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
