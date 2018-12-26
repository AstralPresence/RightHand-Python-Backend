
from flask import Flask
import json
from flask_mongoengine import MongoEngine
from pymongo import MongoClient
from flask_cors import CORS
from flask_security import MongoEngineUserDatastore
from flask_mqtt import Mqtt

#logging for flask-cors
#logging.basicConfig(level=logging.INFO)

#app initialisation
app = Flask(__name__)

#configFiles
app.config.from_pyfile('config.py')

#Mqtt instance
#mqtt = Mqtt(app)

#mongoengine instance
db = MongoEngine(app)
#client = MongoClient('localhost', 27017)
#mongo = client.rhDB


#flask-cors initialization
CORS(app, supports_credentials=True)                       #cookies enabled during initialization

#importing views
from views import *
from models import *

"""
@mqtt.on_connect()
def handle_connect(client, userdata, flags, rc):
    print("mqtt connected")
    groups = Controls.objects.count()
    cont = (Controls.objects())
    group = []
    for i in range(groups):
        group.append(cont[i].groupName)
        rooms = len(cont[i].rooms)
        room = []
        for j in range(rooms):
            room.append(cont[i].rooms[j].name)
            controls = len(cont[i].rooms[j].controls)
            status = []
            controlName = []
            displayName = []
            type=[]
            for k in range(controls):
                controlName.append(cont[i].rooms[j].controls[k].name)
                displayName.append(cont[i].rooms[j].controls[k].displayName)
                status.append(cont[i].rooms[j].controls[k].controlStatus)
                type.append(cont[i].rooms[j].controls[k].type)
                mqtt.subscribe(group[i]+'/'+room[j]+'/'+controlName[k])

@mqtt.on_message()
def handle_mqtt_message(client, userdata, message):
    data = dict(
        topic=message.topic,
        payload=message.payload.decode()
    )
    grn = message.topic.split("/")     # grn is group room name

    content=json.loads(data["payload"])
    controlGroup = Controls.objects.get(groupName=grn[0])
    for room in controlGroup.rooms:
        if room['name'] == grn[1]:
            for control in room['controls']:
                if control['name'] == grn[2]:
                    for key in content.keys():
                        if key == 'state':
                            control['controlStatus'] = content['state']
                            control.save()
                            print('Mqtt updated status')
                            return
                        elif key == 'action':
                            if content['key'] == 'requestAccess':
                                id = content['id']
                                if checkFingerAccess(id):
                                    mqtt.publish(data['topic'], jsonify({"action":"allowAccess"}))
                                    return
                                else:
                                    mqtt.publish(data['topic'], jsonify({"action":"denyAccess"}))
                                    return
                            elif content['key'] == 'enrollID':
                                id = content['id']
                                email = content['email']
                                user = user_datastore.find_user(email=idinfo['email'])
                                user_datastore.delete_user(user)
                                user_datastore.create_user(email=user['email'], refreshSecret=user['refreshSecret'], name=user['name'], accessGroupType=user['accessGroupName'], profilePicURL=user['profilePicURL'], fingerID=id)
    print('Mqtt update status failed'+json.dumps(data))

@mqtt.on_log()
def handle_logging(client, userdata, level, buf):
    print(level, buf)

"""


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, use_reloader=True, debug=True)

