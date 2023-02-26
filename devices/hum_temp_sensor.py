import paho.mqtt.client as mqtt
import random
import time
from config import *

mqtt_topic = "GrupoB/hum_temp/data"

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
    client.username_pw_set(broker_user, broker_pass)

    # Configuramos las funciones de callback para los eventos de conexión y publicación
    client.on_connect = on_connect
    client.on_publish = on_publish

    client.connect(mqtt_broker, mqtt_port)

    return client

def enviar_mensaje(mqtt_topic, client):
   # Generar valores aleatorios de temperatura y humedad
    temperatura = round(random.uniform(20, 30), 2)
    humedad = round(random.uniform(40, 60), 2)

    # Crear un mensaje MQTT con los valores de temperatura y humedad
    mensaje = "{0},{1}".format(temperatura, humedad)
    # Conectar al broker MQTT y enviar el mensaje
    client.publish(mqtt_topic, mensaje)


client = conectar()
while True:
    enviar_mensaje(mqtt_topic, client)
    # Esperar un intervalo de tiempo aleatorio entre 5 y 10 segundos
    time.sleep(random.randint(5, 10))