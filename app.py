from flask import Flask
from flask_mongoengine import MongoEngine
from pymongo import MongoClient
from flask_cors import CORS
#from flask_security import MongoEngineUserDatastore
from flask_mqtt import Mqtt

#logging for flask-cors
#logging.basicConfig(level=logging.INFO)

#app initialisation
app = Flask(__name__)

#configFiles
app.config.from_pyfile('config.py')

#Mqtt instance
mqtt = Mqtt(app)

#mongoengine instance
db = MongoEngine(app)
client = MongoClient('localhost', 27017)
mongo = client.RpiServer


#flask-cors initialization
CORS(app, supports_credentials=True)                       #cookies enabled during initialization

#importing views
from views import *

if __name__ == '__main__':
    app.run()