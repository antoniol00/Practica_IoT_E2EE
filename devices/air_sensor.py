import time
import base64
import os
from dotenv import load_dotenv
import json
from faker import Faker
import paho.mqtt.client as mqtt
import threading
import sys
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
args = parser.parse_args()
sys.path.append("..")  # Adds higher directory to python modules path.
from encryption import aead_algorithms, encryption_algorithms, hashes_algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, load_pem_parameters, PublicFormat
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, modes

load_dotenv()  # load environment variables from .env file

# custom json encoder to encode bytes to hex
class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.hex()
        return super().default(obj)


class InvalidSignature(Exception):
    pass


class AirSensor:
    def __init__(self):
        if args.verbose:
            print("Creating new device...")
        self.device_id = self.generateMAC()  # generate a random MAC address
        # create a new client instance with the device id

        if args.verbose:
            print("Connecting to broker...")
        self.client = mqtt.Client(client_id=self.device_id)
        self.client.username_pw_set(os.getenv("BROKER_USER"), os.getenv(
            "BROKER_PASS"))  # set username and password
        # set the on_connect callback function (called when the client connects to the broker)
        self.client.on_connect = self.on_connect
        # set the on_message callback function (called when the client receives a message from the broker)
        self.client.on_message = self.on_message
        self.mqtt_topic_connect = "GrupoB/new_devices/" + \
            self.device_id  # topic to connect to broker
        self.mqtt_topic_connect_platform = "GrupoB/new_devices/platform/" + \
            self.device_id  # topic to connect to broker
        self.mqtt_topic_data = "GrupoB/data/" + self.device_id  # topic to send data
        self.client.connect(os.getenv("MQTT_BROKER"),
                            int(os.getenv("MQTT_PORT")))


        # get device info from user
        name = input("Device name: ")
        location = input("Device location: ")
        type = input("Device type: ")
        while True:
            try:
                self.encryption_mode = input("Encryption mode (AE, AEAD): ")
                if self.encryption_mode not in ['AE', 'AEAD']:
                    raise ValueError
                break
            except ValueError:
                print("Invalid encryption mode. Please try again.")
        if self.encryption_mode == 'AEAD':
            while True:
                try:
                    self.algo_name = input(
                        "AEAD algorithm (chacha, aes-gcm, aes-ccm, aes-ocb3): ")
                    if self.algo_name not in aead_algorithms:
                        raise ValueError
                    break
                except ValueError:
                    print("Invalid AEAD algorithm. Please try again.")
        else:
            self.algo_name = 'aes-256'
        while True:
            try:
                self.hash_name = input(
                    "Hash algorithm (sha-256, sha-512, sha3-256, sha3-512): ")
                if self.hash_name not in hashes_algorithms:
                    raise ValueError
                break
            except ValueError:
                print("Invalid hash algorithm. Please try again.")
        while True:
            try:
                self.dh_algorithm = input(
                    "DH algorithm (dh-2048, dh-3072, dh-4096, ecdh-p256, ecdh-p384, ecdh-p521): ")
                if self.dh_algorithm not in ['dh-2048', 'dh-3072', 'dh-4096', 'ecdh-p256', 'ecdh-p384', 'ecdh-p521']:
                    raise ValueError
                break
            except ValueError:
                print("Invalid DH algorithm. Please try again.")

        # store the DH information for this device
        self.device_info = {
            'parameters': None,
            'private_key': None,
            'public_key': None,
            'platform_public_key': None,
            'session_key': None,
            'aes_key': None,
            'name': name,
            'location': location,
            'type': type,
            'encryption_mode': self.encryption_mode,
            'algo_name': self.algo_name,
            'hash_name': self.hash_name,
            'dh_algorithm': self.dh_algorithm,
            'is_registered': False
        }
    
        thread = threading.Thread(target=self.message_loop)
        thread.daemon = True
        thread.start()

        if args.verbose:
            print("Device created successfully!")
            print('***************************************************************')

    def generateMAC(self):
        fake = Faker()  # create a new Faker instance
        return str(fake.mac_address())  # returns a random MAC address

    def on_connect(self, client, userdata, flags, rc):
        client.subscribe(self.mqtt_topic_connect_platform, qos=1)

    def on_message(self, client, userdata, msg):
        if args.verbose:
            print("Message received: " + msg.topic + " " + str(msg.payload))
        decoded_payload = msg.payload.decode('utf-8')
        msg_dec = json.loads(decoded_payload)
        if msg.topic == self.mqtt_topic_connect_platform and msg_dec["msg_type"] == 'platform_public_key':
            self.device_info['is_registered'] = False
            if args.verbose:
                print("STEP 3. Generating session key from platform public key...")

            if self.device_info['dh_algorithm'].startswith('ecdh'):
                # Generate the keys
                if self.device_info['dh_algorithm'] == 'ecdh-p256':
                    self.device_info['private_key'] = ec.generate_private_key(ec.SECP256K1())
                elif self.device_info['dh_algorithm'] == 'ecdh-p384':
                    self.device_info['private_key'] = ec.generate_private_key(ec.SECP384R1())
                elif self.device_info['dh_algorithm'] == 'ecdh-p521':
                    self.device_info['private_key'] = ec.generate_private_key(ec.SECP521R1())
                self.device_info['public_key'] = self.device_info['private_key'].public_key()
            else:    
                param_bytes = base64.b64decode(msg_dec['dh_parameters'])
                self.device_info['parameters'] = load_pem_parameters(
                    param_bytes, backend=default_backend())

                if args.verbose:
                    print("Generating public key... ")
                # Generate the keys
                self.device_info['private_key'] = self.device_info['parameters'].generate_private_key()
                self.device_info['public_key'] = self.device_info['private_key'].public_key()

            # Decode the public key from the platform
            self.device_info['platform_public_key'] = load_pem_public_key(
                base64.b64decode(msg_dec['platform_public_key']))

            if self.device_info['dh_algorithm'].startswith('ecdh'):
                # Compute the shared key
                self.device_info['session_key'] = self.device_info['private_key'].exchange(
                    ec.ECDH(), self.device_info['platform_public_key'])
            else:
                # Compute the shared key
                self.device_info['session_key'] = self.device_info['private_key'].exchange(
                    self.device_info['platform_public_key'])

            device_pk = self.device_info['public_key'].public_bytes(
                encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)

            # Send the public key to the platform
            data = {
                'msg_type': 'device_public_key',
                'device_public_key':  base64.b64encode(device_pk).decode('utf-8'),
                'device_id': self.device_id
            }

            self.client.publish(self.mqtt_topic_connect,
                                json.dumps(data), qos=1)
            if args.verbose:
                print("STEP 4. Sending public key to platform...")
                print("Message published to topic " +
                  self.mqtt_topic_connect + ": " + str(data))

        if msg.topic == self.mqtt_topic_connect_platform and msg_dec['msg_type'] == 'platform_challenge':
            if args.verbose:
                print("STEP 8. Verifying challenge...")
            # Derive a secret key using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'HMAC DH secret key',
            ).derive(self.device_info['session_key'])

            # Retrieve the message and digest from the received challenge
            received_message = bytes.fromhex(msg_dec['challenge'])
            digest = received_message[-32:]

            # Verify the HMAC
            hmac_key = hkdf[:16]
            h = HMAC(hmac_key, hashes.SHA256())
            h.update(received_message[:-32])
            try:
                h.verify(digest)
                if received_message[:-32] == b'I am the platform, welcome ' + self.device_id.encode():
                    if args.verbose:
                        print('HMAC verified!')
                else:
                    raise InvalidSignature
            except InvalidSignature:
                print('HMAC not verified! Rejecting challenge and exiting...')
                exit(1)

            if args.verbose:
                print("STEP 9. Creating challenge response...")

            # Generate a random challenge
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'HMAC DH secret key',
            ).derive(self.device_info['session_key'])

            self.device_info['aes_key'] = hkdf

            # Compute the HMAC
            hmac_key = hkdf[:16]
            message = ('I am device ' + self.device_id +
                       ' I am going to start our communication now!').encode('utf-8')
            h = HMAC(hmac_key, hashes.SHA256())
            h.update(message)
            digest = h.finalize()

            data = {
                'msg_type': 'device_challenge_response',
                'challenge': message + digest,
                'device_id': self.device_id
            }

            self.client.publish(self.mqtt_topic_connect,
                                json.dumps(data, cls=BytesEncoder), qos=1)
            if args.verbose:
                print("STEP 10. Challenge sent to platform")
                print("Message published to topic " +
                  self.mqtt_topic_connect + ": " + str(data))
                print('Session key: ' + str(self.device_info['session_key']))
            
            self.device_info['is_registered'] = True

    def send_ae_message(self, message, key, client, algo_name, hash_name):
        # create a new encryption algorithm instance
        algo = encryption_algorithms[algo_name](key)
        iv = os.urandom(16)  # generate a random initialization vector
        # create a new encryptor instance
        encryptor = Cipher(algo, modes.CTR(iv)).encryptor()

        # create a new hash algorithm instance
        hash_algo = hashes_algorithms[hash_name]()

        # encrypt the message
        ct = encryptor.update(message) + encryptor.finalize()
        if args.verbose:
            print(f"{ct=}")
        hmac = HMAC(key, hash_algo)  # create a new HMAC instance
        hmac.update(ct)  # update the HMAC with the encrypted message
        signature = hmac.finalize()  # generate the signature
        if args.verbose:
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
        if args.verbose:
            print("Message published to topic " +
              self.mqtt_topic_data + ": " + str(data))

    def send_aead_message(self, message, key, client, aad, algo_name, hash_name):

        nonce = os.urandom(12)  # generate a random nonce
        # create a new AEAD algorithm instance
        algo = aead_algorithms[algo_name](key)

        ct = algo.encrypt(nonce, message, aad)  # encrypt the message
        if args.verbose:
            print(f"{ct=}")

        # create a new hash algorithm instance
        hash_algo = hashes_algorithms[hash_name]()

        hmac = HMAC(key, hash_algo)  # create a new HMAC instance
        hmac.update(ct)  # update the HMAC with the encrypted message
        signature = hmac.finalize()  # generate the signature
        if args.verbose:
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
        if args.verbose:
            print("Message published to topic " +
              self.mqtt_topic_data + ": " + str(data))

    def register_device(self):
        # create the message to send to the platform, containing the device's information in JSON format
        data = {
            'msg_type': 'hello',
            'name': self.device_info['name'],
            'location': self.device_info['location'],
            'type': self.device_info['type'],
            'device_id': self.device_id,
            'encryption_mode': self.device_info['encryption_mode'],
            'encryption_algorithm': self.device_info['algo_name'],
            'hash_algorithm': self.device_info['hash_name'],
            'dh_algorithm': self.device_info['dh_algorithm']
        }

        payload = json.dumps(data)  # convert the dictionary to a JSON string
        # publish the message to the broker
        self.client.publish(self.mqtt_topic_connect, payload, qos=1)
        if args.verbose:
            print("STEP 1. Hello message sent to the platform")
            print("Message published to topic " +
              self.mqtt_topic_connect + ": " + payload)

    def run(self):
        self.register_device()  # begin registration process
        self.client.loop_forever()  # start the MQTT client loop

    def message_loop(self):
        while True:
            if not self.device_info['is_registered']:
                continue
            # generate a random CO2 level
            co2_level = fake.random_int(min=400, max=2000)
            # generate a random message
            message = "C02 level: {} ppm".format(co2_level).encode('utf-8')
            # generate a random aad
            aad = self.device_id.encode('utf-8')

            if self.device_info['encryption_mode'] == 'AE':
                self.send_ae_message(
                    message, self.device_info['aes_key'], self.client, self.device_info['algo_name'], self.device_info['hash_name'])
            else:
                self.send_aead_message(
                    message, self.device_info['aes_key'], self.client, aad, self.device_info['algo_name'], self.device_info['hash_name'])

            # wait 5 seconds before sending the next message
            time.sleep(5)


fake = Faker()  # create a new Faker instance - this will be used to generate random data to send to the platform
air_sensor = AirSensor()  # create a new air sensor instance
air_sensor.run()  # start the air sensor execution
