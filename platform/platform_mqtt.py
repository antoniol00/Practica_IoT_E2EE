import base64
import os
from dotenv import load_dotenv
import paho.mqtt.client as mqtt
import json
import sys
import threading
import time
from datetime import datetime, timedelta
sys.path.append("..")  # Adds higher directory to python modules path.
from encryption import encryption_algorithms, hashes_algorithms, aead_algorithms
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat, load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from app import *

load_dotenv()  # load environment variables from .env file

# custom json encoder to encode bytes to hex


class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.hex()
        return super().default(obj)


class Platform:

    def __init__(self):
        print("Creating new mqtt in platform...")
        # create a new mqtt client
        self.client = mqtt.Client(client_id="IOT Platform", clean_session=True)
        self.client.username_pw_set(os.getenv("BROKER_USER"), os.getenv(
            "BROKER_PASS"))  # set username and password
        # set the on_connect callback function (called when the client connects to the broker)
        self.client.on_connect = self.on_connect
        # set the on_message callback function (called when the client receives a message from the broker)
        self.client.on_message = self.on_message
        self.client.connect(os.getenv("MQTT_BROKER"),
                            int(os.getenv("MQTT_PORT")))
        self.devices = {}  # devices dictionary
        print("Mqtt client created!\n**************************************************\nWaiting for devices to register...")

        # start key rotation thread
        thread = threading.Thread(target=self.key_rotation)
        thread.daemon = True
        thread.start()

    def on_connect(self, client, userdata, flags, rc):
        # topics where the platform will receive register requests from devices
        client.subscribe("GrupoB/new_devices/*", qos=1)
        # topics where the platform will receive data from devices
        client.subscribe("GrupoB/data/*", qos=1)

    def decrypt_aead(self, message, key, msg_dec):

        # Get algorithms
        try:
            result = json.loads(message)
        except ValueError:
            print(
                "A message was recieved with the data topic, but it was formatted incorrectly")
            return
        try:
            algo = aead_algorithms.get(result['algo_name'])(key)
            hash_algo = hashes_algorithms[result['hash_name']]()
        except KeyError:
            print(
                f"Tried to use unknown algorithm: '{result['algo_name']}' or unknown hash '{result['hash_name']}'")
            return

        # Check signature
        h = HMAC(key, algorithm=hash_algo)
        h.update(bytes.fromhex(result['ct']))
        try:
            h.verify(bytes.fromhex(result['signature']))
        except InvalidSignature:
            print("Recieved encrypted message with invalid signature")
            return
        # Decrypt

        plaintext = algo.decrypt(
            bytes.fromhex(result['nonce']),
            bytes.fromhex(result['ct']),
            result['aad'].encode('utf-8')).decode('utf-8')
        with app.app_context():
            device = Device.query.filter_by(
                id=msg_dec['device_id']).first()
            message = Message(plaintext, device, result['aad'])
            db.session.add(message)
            db.session.commit()
        print(f"Recieved the following encrypted message {plaintext}")
        print(
            f"Also receiced some additional unencrypted data: {result['aad']}")

    def decrypt_ae(self, message, key, msg_dec):

        # Get algorithms
        try:
            result = json.loads(message)
        except ValueError:
            print(
                "A message was recieved with the data topic, but it was formatted incorrectly")
            return
        try:
            algo = encryption_algorithms.get(result['algo_name'])(key)
            hash_algo = hashes_algorithms[result['hash_name']]()
        except KeyError:
            print(
                f"Tried to use unknown algorithm: '{result['algo_name']}' or unknown hash '{result['hash_name']}'")
            return

        # Check signature
        h = HMAC(key, algorithm=hash_algo)
        h.update(bytes.fromhex(result['ct']))
        try:
            h.verify(bytes.fromhex(result['signature']))
        except InvalidSignature:
            print("Recieved encrypted message with invalid signature")
            return

        # Decrypt
        decryptor = Cipher(algo, mode=modes.CTR(
            bytes.fromhex(result['iv']))).decryptor()
        plaintext = decryptor.update(bytes.fromhex(
            result['ct'])) + decryptor.finalize()
        with app.app_context():
            device = Device.query.filter_by(
                id=msg_dec['device_id']).first()
            message = Message(plaintext.decode(), device, None)
            db.session.add(message)
            db.session.commit()
        print(f"Recieved the following encrypted message: {plaintext}")

    def on_message(self, client, userdata, msg):
        print("Message received: " + msg.topic + " " + str(msg.payload))
        decoded_payload = msg.payload.decode('utf-8')
        msg_dec = json.loads(decoded_payload)

        if msg.topic.startswith("GrupoB/data"):
            with app.app_context():
                device = Device.query.filter_by(
                    id=msg_dec['device_id']).first()
                if device == None and msg_dec['device_id'] in self.devices:
                    del self.devices[msg_dec['device_id']]
                if msg_dec['device_id'] not in self.devices or self.devices[msg_dec['device_id']]['is_registered'] == False:
                    print("Recieved data from unregistered device")
                    return
                if msg_dec['enc'] == 'AE':
                    self.decrypt_ae(
                        msg.payload, self.devices[msg_dec['device_id']]['aes_key'], msg_dec)
                elif msg_dec['enc'] == 'AEAD':
                    self.decrypt_aead(
                        msg.payload, self.devices[msg_dec['device_id']]['aes_key'], msg_dec)
                else:
                    print(
                        f"Recieved data from device with unknown message type: {msg_dec['msg_type']}")
                    return

        elif msg.topic.startswith("GrupoB/new_device"):
            if msg_dec['msg_type'] == 'hello':
                self.register_device(msg_dec)
            elif msg_dec['msg_type'] == 'device_public_key':
                self.send_dh_challenge(msg_dec)
            elif msg_dec['msg_type'] == 'device_challenge_response':
                self.verify_dh_challenge_response(msg, msg_dec)
        else:
            ValueError(f"Unrecognized topic: {msg.topic}")

    def register_device(self, msg_dec):
        if msg_dec['device_id'] in self.devices:  # check if the device is already registered
            print(f"Device {msg_dec['device_id']} already registered")
            return

        print("Starting registration of new device with id " +
              msg_dec['device_id'] + "...")
        # Add the device to the devices dictionary
        self.devices[msg_dec['device_id']] = {
            'name': msg_dec['name'],
            'location': msg_dec['location'],
            'type': msg_dec['type'],
            'mqtt_topic': 'GrupoB/new_devices/platform/' + msg_dec['device_id'],
            'device_public_key': None,
            'session_key': None,
            'is_registered': False,
            'aes_key': None,
            'encryption_mode': msg_dec['encryption_mode'],
            'encryption_algorithm': msg_dec['encryption_algorithm'],
            'hash_algorithm': msg_dec['hash_algorithm'],
            'dh_algorithm': msg_dec['dh_algorithm'],
            'last_update': datetime.now()
        }

        print("Generating new DH parameters... (this may take a while)")
        self.generate_new_dh_parameters(msg_dec['dh_algorithm'])  # generate new DH parameters

        platform_pk = self.platform_public_key.public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)

        # Send the platform public key to the device
        if msg_dec['dh_algorithm'].startswith('ecdh'):
            data = {
                'msg_type': 'platform_public_key',
                'platform_public_key': base64.b64encode(platform_pk).decode('utf-8')
            }
        else:
            data = {
                'msg_type': 'platform_public_key',
                'dh_parameters': base64.b64encode(self.param_bytes).decode('utf-8'),
                'platform_public_key': base64.b64encode(platform_pk).decode('utf-8')
            }

        self.client.publish(
            self.devices[msg_dec['device_id']]['mqtt_topic'], json.dumps(data), qos=1)
        print("STEP 2. Platform public key sent to device " +
              msg_dec['device_id'])
        print("Message published to topic " +
              self.devices[msg_dec['device_id']]['mqtt_topic'] + ": " + str(data))

    def send_dh_challenge(self, msg_dec):
        print("STEP 5. Generating session key from device public key...")
        # Decode the public key
        self.devices[msg_dec['device_id']]['device_public_key'] = load_pem_public_key(
            base64.b64decode(msg_dec['device_public_key']))

        if self.devices[msg_dec['device_id']]['dh_algorithm'].startswith('ecdh'):
            self.devices[msg_dec['device_id']]['session_key'] = self.platform_private_key.exchange(ec.ECDH(),
                                                                                                   self.devices[msg_dec['device_id']]['device_public_key'])
        else:
            # Compute the shared key
            self.devices[msg_dec['device_id']]['session_key'] = self.platform_private_key.exchange(
                self.devices[msg_dec['device_id']]['device_public_key'])

        print("STEP 6. Generating challenge for device " +
              msg_dec['device_id'] + "...")
        # Generate a random challenge
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'HMAC DH secret key',
        ).derive(self.devices[msg_dec['device_id']]['session_key'])
        self.devices[msg_dec['device_id']]['aes_key'] = hkdf

        # Compute the HMAC
        hmac_key = hkdf[:16]
        message = ('I am the platform, welcome ' +
                   msg_dec['device_id']).encode('utf-8')
        h = HMAC(hmac_key, hashes.SHA256())
        h.update(message)
        digest = h.finalize()

        data = {
            'msg_type': 'platform_challenge',
            'challenge': message + digest
        }

        self.client.publish(self.devices[msg_dec['device_id']]['mqtt_topic'], json.dumps(
            data, cls=BytesEncoder), qos=1)
        print("STEP 7. Challenge sent to device " + msg_dec['device_id'])
        print("Message published to topic " +
              self.devices[msg_dec['device_id']]['mqtt_topic'] + ": " + str(data))

    def verify_dh_challenge_response(self, msg,  msg_dec):
        # Derive a secret key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'HMAC DH secret key',
        ).derive(self.devices[msg_dec['device_id']]['session_key'])

        # Retrieve the message and digest from the received challenge
        received_message = bytes.fromhex(msg_dec['challenge'])
        digest = received_message[-32:]

        # Verify the HMAC
        hmac_key = hkdf[:16]
        h = HMAC(hmac_key, hashes.SHA256())
        h.update(received_message[:-32])
        try:
            h.verify(digest)
            if received_message[:-32] == b'I am device ' + msg_dec['device_id'].encode('utf-8') + b' I am going to start our communication now!':
                print('HMAC verified!')
                with app.app_context():
                    if Device.query.filter_by(id=msg_dec['device_id']).first() is not None:
                        device = Device.query.filter_by(
                            id=msg_dec['device_id']).first()
                        device.date_register = datetime.now()
                        self.devices[msg_dec['device_id']]['last_update'] = datetime.now()
                        db.session.commit()
                        print('Device ' + msg_dec['device_id'] +
                              ' updated registered!')
                        print("New session key: " +
                              str(self.devices[msg_dec['device_id']]['session_key']))
                        return
                    device = Device(msg_dec['device_id'], self.devices[msg_dec['device_id']]['name'],
                                    self.devices[msg_dec['device_id']
                                                 ]['location'], self.devices[msg_dec['device_id']]['type'],
                                    self.devices[msg_dec['device_id']
                                                 ]['encryption_mode'],
                                    self.devices[msg_dec['device_id']
                                                 ]['encryption_algorithm'],
                                    self.devices[msg_dec['device_id']
                                                 ]['hash_algorithm'],
                                    self.devices[msg_dec['device_id']]['dh_algorithm'])

                    db.session.add(device)
                    db.session.commit()
                print('Device ' + msg_dec['device_id'] +
                      ' successfully registered!')
                print("Session key: " +
                      str(self.devices[msg_dec['device_id']]['session_key']))
                self.devices[msg_dec['device_id']]['is_registered'] = True
            else:
                raise InvalidSignature
        except InvalidSignature:
            print('HMAC not verified! Rejecting challenge and deleting device...')
            del self.devices[msg_dec['device_id']]

    def generate_new_dh_parameters(self, algo):
        if algo.startswith('ecdh'):
            if algo == 'ecdh-p256':
                self.platform_private_key = ec.generate_private_key(ec.SECP256K1())
            elif algo == 'ecdh-p384':
                self.platform_private_key = ec.generate_private_key(ec.SECP384R1())
            elif algo == 'ecdh-p521':
                self.platform_private_key = ec.generate_private_key(ec.SECP521R1())
            self.platform_public_key = self.platform_private_key.public_key()
            return
        if algo == 'dh-2048':
            self.params = dh.generate_parameters(generator=2, key_size=2048)
        elif algo == 'dh-3072':
            self.params = dh.generate_parameters(generator=2, key_size=3072)
        elif algo == 'dh-4096':
            self.params = dh.generate_parameters(generator=2, key_size=4096)
        self.param_bytes = self.params.parameter_bytes(
            Encoding.PEM, ParameterFormat.PKCS3)
        self.platform_private_key = self.params.generate_private_key()
        self.platform_public_key = self.platform_private_key.public_key()

    def key_rotation(self):
        while True:
            # Get the current time
            current_time = datetime.now()

            for dev in self.devices:

                # If the device is registered and the last update was more than 5 minutes ago
                if self.devices[dev]['is_registered'] and (current_time - self.devices[dev]['last_update']).total_seconds() > int(os.getenv("RENEWAL_TIME")):
                    print("Key rotation for device " + dev + " is required...")
                    print("STEP 1. Update the DH parameters for device " + dev)
                    # Generate new DH parameters
                    self.generate_new_dh_parameters(
                        self.devices[dev]['dh_algorithm'])
                    # Send the platform public key to the device
                    platform_pk = self.platform_public_key.public_bytes(
                        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
                    # The message will also include a HMAC using the old session key to prevent impersonation (a paltform could send this message to a device)
                    print("Generating challenge for device " + dev + "...")
                    # Generate a random challenge
                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'HMAC DH secret key',
                    ).derive(self.devices[dev]['session_key'])
                    self.devices[dev]['aes_key'] = hkdf

                    # Compute the HMAC
                    hmac_key = hkdf[:16]
                    message = ('I am the platform, we are going to renew your key ' +
                            dev).encode('utf-8')
                    h = HMAC(hmac_key, hashes.SHA256())
                    h.update(message)
                    digest = h.finalize()

                    # Send the challenge to the device
                    if self.devices[dev]['dh_algorithm'].startswith('ecdh'):
                        data = {
                            'msg_type': 'platform_public_key',
                            'renewal': True,
                            'platform_public_key': base64.b64encode(platform_pk).decode('utf-8'),
                            'challenge': message + digest
                        }
                    else:
                        data = {
                            'msg_type': 'platform_public_key',
                            'renewal': True,
                            'dh_parameters': base64.b64encode(self.param_bytes).decode('utf-8'),
                            'platform_public_key': base64.b64encode(platform_pk).decode('utf-8'),
                            'challenge': message + digest
                        }

                    self.client.publish(
                        self.devices[dev]['mqtt_topic'], json.dumps(data, cls=BytesEncoder), qos=1)
                    print("STEP 2. Platform public key and renewal challenge sent to device " +
                          dev)
                    print("Message published to topic " +
                          self.devices[dev]['mqtt_topic'] + ": " + str(data))
            time.sleep(5)


platform = Platform()
platform.client.loop_forever()
