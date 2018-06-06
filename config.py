

DEBUG = True
SECRET_KEY = 'very_big_secret'
HOST = '0.0.0.0'
PORT = 5000

#Mqtt
MQTT_BROKER_URL = '0.0.0.0'
MQTT_BROKER_PORT = 1883
MQTT_USERNAME = ''  # set the username here if you need authentication for the broker
MQTT_PASSWORD = ''  # set the password here if the broker demands authentication
MQTT_KEEPALIVE = 5  # set the time interval for sending a ping to the broker to 5 seconds
MQTT_TLS_ENABLED = False  # set TLS to disabled for testing purposes

#mongoengine
MONGODB_DB = 'RpiServer'
MONGODB_HOST = '0.0.0.0'
MONGODB_PORT = 27017