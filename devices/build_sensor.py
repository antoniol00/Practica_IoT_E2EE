import argparse
parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
args = parser.parse_args()

import sys
sys.path.append("..")  # Adds higher directory to python modules path.
from encryption import aead_algorithms, encryption_algorithms, hashes_algorithms, key_ex_algorithms

from air_sensor import AirSensor
from hum_temp_sensor import HumTempSensor


# get device info from user
name = input("Device name: ")
location = input("Device location: ")


while ((type := input("Device type: (air, hum_temp):" ))
            not in ['air', 'hum_temp']):
        print("Invalid device type. Please try again.")

use_custom_algos = input("Use default algorithm configuration? (y/n):")

if use_custom_algos == 'n':
    while ((encryption_mode := input("Encryption mode (AE, AEAD): ") )
            not in ['AE', 'AEAD']):
        print("Invalid encryption mode. Please try again.")
    
    if encryption_mode == 'AEAD':
        while ((encryption_algo := input(f"AEAD algorithm ({(', ').join(aead_algorithms)}): "))
            not in aead_algorithms):
            print("Invalid AEAD algorithm. Please try again.")
    else:
        while ((encryption_algo := input(f"AE algorithm ({(', ').join(encryption_algorithms)}): "))
                not in encryption_algorithms):
            print("Invalid AE algorithm. Please try again.")
    while ((hash_algo := input(f"Hash algorithm ({(', ').join(hashes_algorithms)}): "))
                not in hashes_algorithms):
            print("Invalid hash algorithm. Please try again.")
    while ((key_ex_algo := input(f"Key exchange algorithm ({(', ').join(key_ex_algorithms)}): "))
                not in key_ex_algorithms):
            print("Invalid key exchange algorithm. Please try again.")
else:
    encryption_mode = 'AEAD'
    encryption_algo = 'chacha'
    hash_algo = 'sha-256'
    key_ex_algo = 'dh-2048'

if type == 'air':
     algo = AirSensor(name, location, encryption_mode, encryption_algo, hash_algo, key_ex_algo, args.verbose)
else:
     algo = HumTempSensor(name, location, encryption_mode, encryption_algo, hash_algo, key_ex_algo, args.verbose)

algo.run()

