import sys
sys.path.append("..") # Adds higher directory to python modules path.
import paho.mqtt.client as mqtt
from faker import Faker
import json
from dotenv import load_dotenv
import os
from encryption import aead_algorithms, encryption_algorithms, hashes
import json
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.hmac import HMAC

mqtt_topic = "GrupoB/new_device"
key = b'\xec\xc9\x9e\x98\x8d\x0e\xd2~\x99H\x13\x81%F\x16\xf7\xabbs\x15\x10\x0eP\rL\xeew\x03\xab.*\xff'

load_dotenv()  # carga las variables de entorno desde el archivo .env

# Definimos una función para manejar el evento on_connect del cliente MQTT


def on_connect(client, userdata, flags, rc):
    print("Conectado al broker MQTT con código de resultado: " + str(rc))

    # Suscribirse al tema deseado
    client.subscribe(mqtt_topic)

# Definimos una función para manejar el evento on_publish del cliente MQTT


def on_publish(client, userdata, mid):
    print("Mensaje publicado con éxito en el tema: " + mqtt_topic)


def conectar():
    client = mqtt.Client()
    # Configuramos el nombre de usuario y contraseña para la conexión al broker
    client.username_pw_set(os.getenv("BROKER_USER"), os.getenv("BROKER_PASS"))

    # Configuramos las funciones de callback para los eventos de conexión y publicación
    client.on_connect = on_connect
    client.on_publish = on_publish

    client.connect(os.getenv("MQTT_BROKER"), int(os.getenv("MQTT_PORT")))

    return client


def enviar_mensaje_ae(message, key, client, algo_name='aes-256', hash_name='sha-256'):
    algo = encryption_algorithms[algo_name](key)
    iv = os.urandom(16)
    encryptor = Cipher(algo, modes.CTR(iv)).encryptor()

    hash_algo = hashes[hash_name]()
    
    ct =  encryptor.update(message) + encryptor.finalize()
    print(f"{ct=}")
    hmac = HMAC(key, hash_algo)
    hmac.update(ct)
    signature = hmac.finalize()
    print(signature)

    client.publish("ae", json.dumps({'iv': iv.hex(),
                                       'ct': ct.hex(),
                                       'signature': signature.hex(),
                                       'algo_name': algo_name,
                                       'hash_name': hash_name,
                                       }))


def enviar_mensaje_aad(message, key, client, aad=b'', algo_name='chacha'):
    # Generar una señal aleatoria de 0 o 1 para representar la presencia o ausencia de movimiento
    # Crear un mensaje MQTT con la señal de movimiento

    nonce = os.urandom(12)
    algo = aead_algorithms[algo_name](key)

    ct = algo.encrypt(nonce, message, aad)

    # Conectar al broker MQTT y enviar el mensaje
    client.publish("aead", json.dumps({'nonce': nonce.hex(),
                                       'ct': ct.hex(),
                                       'algo_name': algo_name,
                                       'aad': aad.decode('utf-8'
                                                         )}))


def registrar_dispositivo():
    # Define los datos a enviar en el objeto JSON
    data = {
        "nombre": "Aire0" + str(fake.random_int(min=0, max=9)),
        "ubicacion": "sala",
        "tipo": "Sensor de calidad del aire"
    }
    # Codifica el objeto JSON
    payload = json.dumps(data)
    # Conectar al broker MQTT y enviar el mensaje
    client.publish(mqtt_topic, payload)


fake = Faker()
client = conectar()
registrar_dispositivo()

co2_level = fake.random_int(min=400, max=2000)
algo = "chacha" if fake.random_int(min=0, max=1) == 1 else "aes-gcm"

message = "Nivel de CO2: {} ppm".format(co2_level).encode('utf-8')
aad = b"todos pueden leerlo"
enviar_mensaje_aad(message, key, client, aad, algo)
enviar_mensaje_ae(message, key, client)

'''
while True:
    enviar_mensaje(mqtt_topic, client)
    # Esperar un intervalo de tiempo fijo de 1 segundo
    time.sleep(1)
'''
