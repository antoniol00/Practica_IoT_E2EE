import paho.mqtt.client as mqtt
import random
import time
from datetime import datetime
from config import *

mqtt_topic = "temperatura-a-ajustar"
mqtt_sub_topic = "temperatura-actual"

# Definir los límites de temperatura según la hora del día y la estación del año
TEMPERATURA_NOCTURNA = 22
TEMPERATURA_DIURNA = 20
TEMPERATURA_MAXIMA_VERANO = 26
TEMPERATURA_MINIMA_VERANO = 18
TEMPERATURA_MAXIMA_INVIERNO = 24
TEMPERATURA_MINIMA_INVIERNO = 16

def ajustar_temperatura(temperatura_actual, temporada, hora):
    # Ajustar la temperatura según la hora del día y la estación del año
    if temporada == "verano":
        if hora >= 20 or hora < 6:
            temperatura_deseada = TEMPERATURA_MINIMA_VERANO
        else:
            temperatura_deseada = min(max(temperatura_actual - 1, TEMPERATURA_MINIMA_VERANO), TEMPERATURA_MAXIMA_VERANO)
    else:
        if hora >= 20 or hora < 6:
            temperatura_deseada = TEMPERATURA_NOCTURNA
        else:
            temperatura_deseada = min(max(temperatura_actual + 1, TEMPERATURA_MINIMA_INVIERNO), TEMPERATURA_MAXIMA_INVIERNO)
    return temperatura_deseada

def on_message(client, userdata, message):
    # Función que se llama cuando se recibe un mensaje en el tema suscrito
    temperatura_actual = float(message.payload.decode())
    temporada = "verano" if datetime.now().month >= 6 and datetime.now().month <= 9 else "invierno"
    hora = datetime.now().hour
    temperatura_deseada = ajustar_temperatura(temperatura_actual, temporada, hora)
    print("Temperatura actual: {0}°C - Temperatura deseada: {1}°C".format(temperatura_actual, temperatura_deseada))
    client.publish(mqtt_topic, str(temperatura_deseada))

def main():
    # Conectar al broker MQTT y suscribirse al tema correspondiente
    client = mqtt.Client(client_id=mqtt_client_id)
    client.connect(mqtt_broker, mqtt_port)
    client.subscribe(mqtt_sub_topic)
    client.on_message = on_message
    client.loop_start()

    # Esperar a que el usuario ingrese una temperatura o interrumpir la ejecución con CTRL+C
    try:
        while True:
            temperatura_manual = input("Ingrese la temperatura deseada (o presione ENTER para salir): ")
            if temperatura_manual == "":
                break
            try:
                temperatura_deseada = float(temperatura_manual)
                client.publish(mqtt_topic, str(temperatura_deseada))
                print("Temperatura deseada: {0}°C".format(temperatura_deseada))
            except ValueError:
                print("Valor de temperatura no válido")
    except KeyboardInterrupt:
        pass

