import sys
import json
import os
sys.path.append("..")  # Adds higher directory to python modules path.

from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.hmac import HMAC
from encryption import aead_algorithms, encryption_algorithms, hashes_algorithms


def send_ae_message(self, message, key, client, algo_name, hash_name, verbose):
    # create a new encryption algorithm instance
    algo = encryption_algorithms[algo_name](key)
    iv = os.urandom(16)  # generate a random initialization vector
    # create a new encryptor instance
    encryptor = Cipher(algo, modes.CTR(iv)).encryptor()

    # create a new hash algorithm instance
    hash_algo = hashes_algorithms[hash_name]()

    # encrypt the message
    ct = encryptor.update(message) + encryptor.finalize()
    if verbose:
        print(f"{ct=}")
    hmac = HMAC(key, hash_algo)  # create a new HMAC instance
    hmac.update(ct)  # update the HMAC with the encrypted message
    signature = hmac.finalize()  # generate the signature
    if verbose:
        print(f"{signature=}")

    data = {'enc': 'AE',
            'iv': iv.hex(),
            'ct': ct.hex(),
            'signature': signature.hex(),
            'algo_name': algo_name,
            'hash_name': hash_name,
            'device_id': self.device_id
            }
    # publish the message to the broker
    self.client.publish(self.mqtt_topic_data, json.dumps(data))
    if verbose:
        print("Message published to topic " +
            self.mqtt_topic_data + ": " + str(data))
        

def send_aead_message(self, message, key, client, aad, algo_name, hash_name, verbose):

    nonce = os.urandom(12)  # generate a random nonce
    # create a new AEAD algorithm instance
    algo = aead_algorithms[algo_name](key)

    ct = algo.encrypt(nonce, message, aad)  # encrypt the message
    if verbose:
        print(f"{ct=}")

    # create a new hash algorithm instance
    hash_algo = hashes_algorithms[hash_name]()

    hmac = HMAC(key, hash_algo)  # create a new HMAC instance
    hmac.update(ct)  # update the HMAC with the encrypted message
    signature = hmac.finalize()  # generate the signature
    if verbose:
        print(f"{signature=}")

    data = {'enc': 'AEAD',
            'nonce': nonce.hex(),
            'ct': ct.hex(),
            'signature': signature.hex(),
            'device_id': self.device_id,
            'algo_name': algo_name,
            'hash_name': hash_name,
            'aad': aad.decode('utf-8'
            )}
    self.client.publish(self.mqtt_topic_data, json.dumps(data))  # publish the message to the broker
    if verbose:
        print("Message published to topic " +
            self.mqtt_topic_data + ": " + str(data))
