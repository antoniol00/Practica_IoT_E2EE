import paho.mqtt.client as mqtt

# Definimos algunas constantes
BROKER_HOST = "broker.shiftr.io"
BROKER_PORT = 1883
BROKER_USER = "tu-usuario"
BROKER_PASS = "tu-contraseña"
TOPIC = "/test/topic"
MESSAGE = "Hola, mundo!"

# Definimos una función para manejar el evento on_connect del cliente MQTT
def on_connect(client, userdata, flags, rc):
    print("Conectado al broker MQTT con código de resultado: " + str(rc))

    # Suscribirse al tema deseado
    client.subscribe(TOPIC)

# Definimos una función para manejar el evento on_publish del cliente MQTT
def on_publish(client, userdata, mid):
    print("Mensaje publicado con éxito en el tema: " + TOPIC)

# Creamos un nuevo cliente MQTT
client = mqtt.Client()

# Configuramos el nombre de usuario y contraseña para la conexión al broker
client.username_pw_set(BROKER_USER, BROKER_PASS)

# Configuramos las funciones de callback para los eventos de conexión y publicación
client.on_connect = on_connect
client.on_publish = on_publish

# Conectamos al broker MQTT
client.connect(BROKER_HOST, BROKER_PORT)

# Publicamos un mensaje en el tema deseado
client.publish(TOPIC, MESSAGE)

# Iniciamos el bucle de eventos del cliente MQTT
client.loop_forever()
