import time
from sensor import Sensor
class AirSensor(Sensor):
    def message_loop(self):
        while True:
            if not self.device_info['is_registered']:
                continue
            # generate a random CO2 level
            co2_level = self.fake.random_int(min=400, max=2000)
            # generate a random message
            message = "C02 level: {} ppm".format(co2_level).encode('utf-8')
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
        return 'air'