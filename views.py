from app import app
from functools import wraps

from models import User, Role, AccessGroup, Controls, Rooms, Control, Time, Access
from flask_security import MongoEngineUserDatastore, UserMixin, RoleMixin
from flask import request, jsonify, redirect, Response
import random
import time
from jose import jwt
from google.oauth2 import id_token
from google.auth.transport import requests
from app import mongo, db


CLIENT_ID = "25667199244-6vrfmn6kif5psmu2p8q3t8v5q9701sat.apps.googleusercontent.com"
QRKey = 'mhUfnCAM2gid8PomMTP25c8N9xVsGRHYX5NwQfMPZpVhDWttj0kpqpYwIpk2LnX1GFpLD8ohG1a6GMkTcfd6y3uvD7sdXawvoC5Tdau2IK4f8SkamnaZ9qUgXiDL'
secret = 'mhUfnCAM2gid8PomK4f8SkamnaZ9qUgXiDL'
CLIENT_ID_AND = "25667199244-p8raa6qo18obknafb6ffig35osflb44t.apps.googleusercontent.com"
CLIENT_ID_IOS = "25667199244-hgg2edbv9sjjrf9v0s059e6apqmccbol.apps.googleusercontent.com"
CLIENT_ID_WEB = "25667199244-cdfjnlg8hlijes010n00l6843h9r5p5m.apps.googleusercontent.com"
def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'Authorization' in request.headers:
            auth = request.headers['Authorization']
            print(auth)
            if not check_auth(auth):
                return authenticate()
        else:
            return authenticate()
        return f(*args, **kwargs)

    return decorated


def check_auth(accessToken):
    try:
        global payload, current_user
        payload = jwt.decode(accessToken, secret)
        print(payload)
        current_user = user_datastore.find_user(email=payload['email'])
    except jwt.ExpiredSignatureError:
        return False
    return True


def decodeControls(control):
    data = [0, 0]
    j = 0
    for i in range(len(control)):
        if control[i] == '/':
            data[j] = i
            j = j + 1
    group = control[0:(data[0])]
    room = control[(data[0] + 1):(data[1])]
    controlName = control[(data[1] + 1):]
    return [group, room, controlName]


user_datastore = MongoEngineUserDatastore(db, User, Role)


@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    content = request.get_json(force=True)  # QRKey and idToken
    print(content)
    token = content['idToken']

    try:
    	idinfo = id_token.verify_oauth2_token(token, requests.Request())
    	if idinfo['aud'] not in [CLIENT_ID_IOS, CLIENT_ID_AND, CLIENT_ID_WEB]:
        	raise ValueError('Could not verify audience.')

    	if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
        	raise ValueError('Wrong issuer.')

    	# ID token is valid. Get the user's Google Account ID from the decoded token.
    	userid = idinfo['sub']
    except ValueError:
    	print('value error')
   
    print(idinfo['email'])

    if not user_datastore.find_user(email=idinfo['email']):
        if AccessGroup.objects(type='owner'):
            print('User creation Failed. Admin User Found in Database')
            return jsonify({"result": "fail", "message": "Admin User Found in Database"})
        else:
            print("First User Creation")
            qrToken = content['qrToken']
            qrKey = jwt.decode(qrToken, secret, algorithms=['HS256'], options={'verify_aud': False})
            if qrKey['qrKey'] == QRKey:
                refreshKey = random.getrandbits(32)

                user_datastore.create_user(email=idinfo['email'], refreshSecret=refreshKey, name=idinfo['name'],
                                           accessGroupType='owner', profilePicURL=idinfo['picture'])

                refreshToken = jwt.encode({'refreshSecret': refreshKey}, 'mhUfnCAM2gid8PomK4f8SkamnaZ9qUgXiDL',
                                          algorithm='HS256')
                return jsonify({"message": refreshToken, "result": "success"})
            else:
                print("Failed user create attempt. QR mismatch")
                return jsonify({"result": "fail", "message": "QR code mismatched"})

    else:
        user = user_datastore.find_user(email=idinfo['email'])
        refreshKey = random.getrandbits(32)
        refreshToken = jwt.encode({'refreshSecret': refreshKey, 'email': idinfo['email']}, secret, algorithm='HS256')
        user_datastore.delete_user(user)
        user_datastore.create_user(email=idinfo['email'], refreshSecret=refreshKey, name=user['name'],
                                   accessGroupType=user['accessGroupType'], profilePicURL=user['profilePicURL'],fingerID =user['fingerID'])
        return jsonify({"message": refreshToken, "result": "success"})


@app.route('/getAccessToken', methods=['POST', 'OPTIONS'])
def getAccessToken():
    content = request.get_json(force=True)
    print(content)
    refreshToken = content['refreshToken']
    payload = jwt.decode(refreshToken, secret)
    print(payload['refreshSecret'])
    user = user_datastore.find_user(refreshSecret=payload['refreshSecret'])

    if not user:
        print("fail")
        return jsonify({"message": "fail"})
    else:
        print(user)
        print(user.email)
        secs = int(time.time())
        accessToken = jwt.encode({'email': user.email, 'exp': secs + 360}, secret, algorithm='HS256')
        return accessToken


@app.route('/accessGroup', methods=['POST', 'OPTIONS'])
def accessGroupMethod():
    content = request.get_json()
    type = content['accessGroupType']
    if type == 'owner':
        if not AccessGroup.objects(name=content['accessGroupName']):
            access = AccessGroup(type=type, name=content['accessGroupName'], UIDs=[content['UIDs']])
            access.save()
            return jsonify({"result": "success", "message": "owner group created"})
        else:
            access = AccessGroup.objects.get(name=content['accessGroupName'])
            try:
                access.UIDs.index(content['UIDs'])
                return jsonify({"results": "fail", "message": "owner group UID exists"})
            except:
                access.UIDs.append(content['UIDs'])
                access.save()
                return jsonify({"results": "success", "message": "owner group appended"})

    elif type == 'other':
        if not AccessGroup.objects(name=content['accessGroupName']):
            access1 = AccessGroup(type=type, name=content['accessGroupName'], UIDs=[content['UIDs']])
            access1.access.control = content['access']['control']
            access1.access = [Access(content['access']['control'], [
                Time(start=content['access']['time']['start'], stop=content['access']['time']['stop'])])]
            access1.save()
            return jsonify({"result": "success", "message": "group created"})
        else:
            access1 = AccessGroup.objects.get(name=content['accessGroupName'])
            try:
                access1.UIDs.index(content['UIDs'])
                print("UIDs already exists")
            except:
                access1.UIDs.append(content['UIDs'])
                access1.save()
                print("Group UIDs updated")

            try:
                access1.access.index(Access(content['access']['control'], [
                    Time(start=content['access']['time']['start'], stop=content['access']['time']['stop'])]))
                print("try")
            except:
                access1.access.append(Access(content['access']['control'], [
                    Time(start=content['access']['time']['start'], stop=content['access']['time']['stop'])]))
                access1.save()

        return jsonify({"result": "success", "message": "updated"})
    else:
        return jsonify({"result": "fail", "message": "Wrong access Group Type"})


'''
{"accessGroupName":"servants",
"accessGroupType":"other",
"UIDs":"hella@gmail.com",
"access":{"control":"light","time":{"start":"0900","stop":"0930"}}}
'''


@app.route('/getControls', methods=['GET', 'OPTIONS'])
@requires_auth
def displayControls():
    content = request.get_json()
    try:
	    email = current_user['email']	    
	    type = current_user.accessGroupType  # accessGroupType
            access_user = AccessGroup.objects.get(type=type)

    except AccessGroup.DoesNotExist:
    	    user = None
	    return jsonify({"message": "access group not found", "result": "fail"})
            
    if type == 'other':

            name = access_user.name  # accessGroupName
            n = len(access_user.access)
            control = []
            group = []
            room = []
            controlName = []
            for i in range(n):
                    control.append(access_user.access[i].control)  # list of control of form group/room/control_name
                    data = decodeControls(control[i])
                    group.append(data[0])
                    room.append(data[1])
                    controlName.append(data[2])
            displayName = []
            controlStatus = []
            for i in range(len(control)):
                    controlsObject = Controls.objects.get(group=group[i])
                    for item in controlsObject.rooms:
                            if item['name'] == room[i]:
                                    break
                    if [item]:
                            for j in range(len(controlsObject.rooms)):
                                    if controlsObject.rooms[j] == item:
                                            break
                            for item1 in controlsObject.rooms[j].controls:
                                    if item1['name'] == controlName[i]:
                                            break
                            if [item1]:
                                    for k in range(len(controlsObject.rooms[j].controls)):
                                            if controlsObject.rooms[j].controls[k] == item1:
                                                    break
                                    displayName.append(controlsObject.rooms[j].controls[k].displayName)
                                    controlStatus.append(controlsObject.rooms[j].controls[k].controlStatus)
            data = []
            for i in range(len(control)):
                    data.append({'type': type, 'name': name, 'status': controlStatus[i], 'displayName': displayName[i],
                                 'group': group[i], 'room': room[i]})
            return jsonify({"message": data, "result": "success"})

    elif type == 'owner':
            email = payload['email']
            access_user = AccessGroup.objects.get(type=type)
            name = access_user.name  # accessGroupName

            groups = Controls.objects.count()
            cont = (Controls.objects())
            group = []
            data = []
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
                        data.append({'type': type[k], 'name': controlName[k], 'status': status[k], 'displayName': displayName[k],
                                     'group': group[i], 'room': room[j]})

            print(data)

            return jsonify({"message": data, "result": "success"})





'''
{"accessToken":"" }
'''

    
@app.route('/editControl', methods=['POST', 'OPTIONS'])
def editControlsMethods():
    content = request.get_json()
    controlGroup = Controls.objects.get(groupName=grn[0])
    for room in controlGroup.rooms:
        if room['name'] == content['room']:
            for control in room['controls']:
                if control['name'] == content['name']:
            	    control['controlStatus'] = content['status']
            	    control['displayName'] = content['displayName']
            	    control.save()
            	    return jsonify({'result': 'success'})

    return jsonify({'result': 'fail', 'message': 'control does not exist'})


'''
{"group":"firstfloor",
"room":"terrace",
"control":{"controlStatus":0,
            "displayName":"socket2",
              "name":"fridge"
             }
}
'''




