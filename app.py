from flask import Flask
from flask_mongoengine import MongoEngine
from pymongo import MongoClient
#from flask_security import MongoEngineUserDatastore
from flask_mqtt import Mqtt


#app initialisation
app = Flask(__name__)

#configFiles
app.config.from_pyfile('config.py')

#Mqtt instance
#mqtt = Mqtt(app)

#mongoengine instance
db = MongoEngine(app)
client = MongoClient('localhost', 27017)
mongo = client.RpiServer

#importing views
from views import *



if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5000,debug = True)

#QR = jwt.encode({'QRKey':'zdRbuffl1SmYkI3NekAS0MjQbW055unXVVks3fb8TbiCMecrqCHAWj2fZ1WYzQ5wBjowlxBTdE2bzmNXFJcekBbLUucJcKJHZ8EhcPASDqalTcN8aAFbEr6U7iym8kCaT3C9EnLrecH3yyjpQVh4ndX1huCtBvFOujE', 'remoteURL': ''},'this_is_secret_for_QR_code',algorithm='HS256')