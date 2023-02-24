import paho.mqtt.client as mqtt
import random
import time
from config import *

def enviar_mensaje(mqtt_topic):
    # Generar valores aleatorios de temperatura y humedad
    temperatura = round(random.uniform(20, 30), 2)
    humedad = round(random.uniform(40, 60), 2)

    # Crear un mensaje MQTT con los valores de temperatura y humedad
    mensaje = "{0},{1}".format(temperatura, humedad)

    # Conectar al broker MQTT y enviar el mensaje
    client = mqtt.Client()
    client.connect(mqtt_broker, mqtt_port)
    client.publish(mqtt_topic, mensaje)
    client.disconnect()

while True:
    enviar_mensaje(mqtt_topic)
    # Esperar 5 segundos antes de enviar el siguiente mensaje
    time.sleep(5)