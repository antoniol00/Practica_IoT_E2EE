import paho.mqtt.client as mqtt
from faker import Faker
import time
from config import *

mqtt_topic = "GrupoB/air/data"

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
    # Generar una señal aleatoria de 0 o 1 para representar la presencia o ausencia de movimiento
    co2_level = fake.random_int(min=400, max=2000)
    # Crear un mensaje MQTT con la señal de movimiento
    mensaje = "Nivel de CO2: {} ppm".format(co2_level)
    print(mensaje)
    # Conectar al broker MQTT y enviar el mensaje
    client.publish(mqtt_topic, mensaje)

fake = Faker()
client = conectar()
while True:
    enviar_mensaje(mqtt_topic, client)
    # Esperar un intervalo de tiempo fijo de 1 segundo
    time.sleep(1)
