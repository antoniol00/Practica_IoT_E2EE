from app import app, Device, db
import json
import paho.mqtt.client as mqtt
from dotenv import load_dotenv
import os

load_dotenv() # carga las variables de entorno desde el archivo .env

def on_connect(client, userdata, flags, rc):
    print("Conectado al broker con código: " + str(rc))
    client.subscribe("GrupoB/new_device")

def on_message(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))
    # Aquí se puede agregar el código para guardar el mensaje en la base de datos
    device_info = json.loads(msg.payload)
    device = Device(nombre=device_info['nombre'], ubicacion=device_info['ubicacion'], tipo=device_info['tipo'])
    with app.app_context():
        db.session.add(device)
        db.session.commit()

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