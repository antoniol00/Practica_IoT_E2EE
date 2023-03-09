import sys
sys.path.append("..") # Adds higher directory to python modules path.
import json
import paho.mqtt.client as mqtt
from dotenv import load_dotenv
import os
from encryption import aead_algorithms, encryption_algorithms, hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.exceptions import InvalidSignature

key=b'\xec\xc9\x9e\x98\x8d\x0e\xd2~\x99H\x13\x81%F\x16\xf7\xabbs\x15\x10\x0eP\rL\xeew\x03\xab.*\xff'

load_dotenv() # carga las variables de entorno desde el archivo .env

def on_connect(client, userdata, flags, rc):
    print("Conectado al broker con código: " + str(rc))
    client.subscribe("GrupoB/new_device")
    client.subscribe("ae")
    client.subscribe("aead")

def decrypt_aead(message, key):

    # Get algorithms
    try:
        result = json.loads(message)
    except ValueError:
        print("A message was recieved with the data topic, but it was formatted incorrectly")
        return
    try:
        algo = aead_algorithms[result['algo_name']](key)
    except KeyError:
        print(f"Tried to use unknown algorithm: {result['algo_name']}")
        return
    
    # Decrypt
    
    plaintext = algo.decrypt(
                            bytes.fromhex(result['nonce']), 
                            bytes.fromhex(result['ct']), 
                            result['aad'].encode('utf-8')).decode('utf-8')
    print(f"Recieved the following encrypted message {plaintext}")
    print(f"Also receiced some additional unencrypted data: {result['aad']}")

def decrypt_ae(message, key):

    # Get algorithms
    try:
        result = json.loads(message)
    except ValueError:
        print("A message was recieved with the data topic, but it was formatted incorrectly")
        return
    try:
        algo = encryption_algorithms.get(result['algo_name'])(key)
        hash_algo = hashes[result['hash_name']]()
    except KeyError:
        print(f"Tried to use unknown algorithm: '{result['algo_name']}' or unknown hash '{result['hash_name']}'")
        return
    
    # Check signature
    h = HMAC(key,algorithm=hash_algo)
    h.update(bytes.fromhex(result['ct']))
    try:
        h.verify(bytes.fromhex(result['signature']))
    except InvalidSignature:
        print("Recieved encrypted message with invalid signature")
        return
    
    # Decrypt
    decryptor = Cipher(algo,mode=modes.CTR(bytes.fromhex(result['iv']))).decryptor()
    plaintext = decryptor.update(bytes.fromhex(result['ct'])) + decryptor.finalize()
    print(f"Recieved the following encrypted message: {plaintext}")

def on_message(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))
    if msg.topic == "aead":
        decrypt_aead(msg.payload, key)
    elif msg.topic == "ae":
        decrypt_ae(msg.payload, key)
    # Aquí se puede agregar el código para guardar el mensaje en la base de datos
    elif msg.topic == 'register':
        device_info = json.loads(msg.payload)
        device = Device(nombre=device_info['nombre'], ubicacion=device_info['ubicacion'], tipo=device_info['tipo'])
        with app.app_context():
            db.session.add(device)
            db.session.commit()
    else:
        ValueError(f"Unrecognized topic: {msg.topic}")

def start_mqtt_client():
    client = mqtt.Client()
    # Configuramos el nombre de usuario y contraseña para la conexión al broker
    client.username_pw_set(os.getenv("BROKER_USER"), os.getenv("BROKER_PASS"))

    # Configuramos las funciones de callback para los eventos de conexión y publicación
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(os.getenv("MQTT_BROKER"), int(os.getenv("MQTT_PORT")))
    client.loop_forever()

start_mqtt_client()