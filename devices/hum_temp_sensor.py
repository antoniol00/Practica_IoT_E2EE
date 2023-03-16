import paho.mqtt.client as mqtt
import random
import time
from config import *

mqtt_topic = "GrupoB/hum_temp/data"

import time
from sensor import Sensor
class HumTempSensor(Sensor):
    def message_loop(self):
        while True:
            if not self.device_info['is_registered']:
                continue

            # Generar valores aleatorios de temperatura y humedad
            temperatura = round(random.uniform(20, 30), 2)
            humedad = round(random.uniform(40, 60), 2)

            # Crear un mensaje MQTT con los valores de temperatura y humedad
            message = "Humidity: {0}%, Temperature: {1}ºC".format(temperatura, humedad).encode('utf-8')
            aad = f"(unencrypted) sent from {self.device_id}".encode('utf-8')

            if self.device_info['encryption_mode'] == 'AE':
                self.send_ae_message(
                    message, self.device_info['aes_key'], self.client, self.device_info['algo_name'], self.device_info['hash_name'])
            else:
                self.send_aead_message(
                    message, self.device_info['aes_key'], self.client, aad, self.device_info['algo_name'], self.device_info['hash_name'])

            # wait 5 seconds before sending the next message
            time.sleep(5)

    def type(self):
        return 'hum_temp'
