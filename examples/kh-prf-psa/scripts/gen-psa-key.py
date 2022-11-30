import os
from pycoin.encoding import hexbytes

psa_key_len = 16*2096

key_file = open('key.txt', 'w')

with open('psa-key.c.temp', 'w') as f:
    f.write('#include "kh-prf-psa-crypto.h"\n\n')
    f.write('const uint8_t psa_key_material[PSA_KEY_LEN_BYTES] = {\n')
    for i in range(psa_key_len//16):
        for j in range(16):
            r = os.urandom(1)
            f.write("0x{}, ".format(hexbytes.b2h(r)))
            key_file.write("{}".format(hexbytes.b2h(r)))
        
        f.write("\n")
        key_file.write("\n")

    f.write("};")
