import csv
from pycoin.ecdsa import secp256r1 as p256
from pycoin.encoding import sec, hexbytes
from pycoin.satoshi import der
from secrets import randbelow

NUM_KEYS = 10000


# open the file in the write mode
f = open('key-pairs.csv', 'w')

# create the csv writer
writer = csv.writer(f)

generator = p256.secp256r1_generator
header = ['id', 'public-key (hex, non compressed)', 'private-key (hex)']
#writer.writerow(header)

#fixed keypair for IoT device
privKey = 0xbd8092a09fab6910483fe6d9baacf77c59532daad8fc1b7c35c806acf7909bed
pubKey = generator * privKey
sec_pub = sec.public_pair_to_sec(pubKey, compressed=False)
row = [1, hexbytes.b2h(sec_pub), format(privKey,'x')]
writer.writerow(row)

for i in range(2,NUM_KEYS+1): # +1 because range is not inclusive
    privKey = randbelow(generator.order())
    pubKey = generator * privKey
    sec_pub = sec.public_pair_to_sec(pubKey, compressed=False)
    row = [i, hexbytes.b2h(sec_pub), format(privKey,'x')]

    # write a row to the csv file
    writer.writerow(row)

# close the file
f.close()

