from app import app
from models import User, AccessGroup, Controls, Rooms, Control, Time, Access
from flask import request, jsonify, redirect
import random
import time
import jwt
from oauth2client import crypt, client
from app import mongo

flow = client.flow_from_clientsecrets('client_secret.json',scope='profile',redirect_uri='http://www.example.com/oauth2callback')
flow.params['access_type'] = 'offline'         # offline access
flow.params['include_granted_scopes'] = True   # incremental auth

CLIENT_ID = "25667199244-6vrfmn6kif5psmu2p8q3t8v5q9701sat.apps.googleusercontent.com"
QRKey = 'mhUfnCAM2gid8PomMTP25c8N9xVsGRHYX5NwQfMPZpVhDWttj0kpqpYwIpk2LnX1GFpLD8ohG1a6GMkTcfd6y3uvD7sdXawvoC5Tdau2IK4f8SkamnaZ9qUgXiDL'
secret = 'mhUfnCAM2gid8PomMTP25c8N9xVsGRHYX5NwQfMPZpVhDWttj0kpqpYwIpk2LnX1GFpLD8ohG1a6GMkTcfd6y3uvD7sdXawvoC5Tdau2IK4f8SkamnaZ9qUgXiDL'

def check_auth(accessToken):

    try:
        global payload, current_user
        payload = jwt.decode(accessToken, secret)
        current_user = User.objects(email=payload['email'])
    except jwt.ExpiredSignatureError:
        return False
    return True

@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    content=request.get_json(force=True)                 #QRKey and idToken
    token=content['idToken']
    qrToken = content['qrToken']
    qrKey = jwt.decode(qrToken, secret)
    print(token)
    try:
        idinfo = client.verify_id_token(token, CLIENT_ID)
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise crypt.AppIdentityError("Wrong issuer.")
    except crypt.AppIdentityError:
        return jsonify({'result':'fail','message':'failed at idtoken verification'})

    print(idinfo['email'])

    if not User.objects(email=idinfo['email']):
        if User.objects(roles = 'admin'):
            print('Login Failed----Admin User Found in Database')
            return jsonify({"result":"fail","message":"Admin User Found in Database"})
        else :
            print("First User Creation")
            if qrKey == QRKey:
                refreshKey = random.getrandbits(32)

                try:
                    user = User(email=idinfo['email'], refreshSecret = refreshKey, name = idinfo['name'], accessGroupType = 'owner', profilePicURL = idinfo['profilePicURL'])
                    user.save()
                except:
                    print("Email already used")
                    return jsonify({"result":"fail","message":"Email already exists"})
                refreshToken = jwt.encode({'refreshSecret':refreshKey,'email':idinfo['email']},secret, algorithm = 'HS256')
                return jsonify({"message":refreshToken, "result":"success"})
            else:
                print("Fail---Go back to Login")
                return jsonify({"result":"fail","message":"Fail---Go back to Login"})

    else :
        user = User(email=idinfo['email'])
        refreshKey = user.refreshSecret
        refreshToken = jwt.encode({'refreshSecret': refreshKey, 'email': idinfo['email']},secret, algorithm='HS256')
        return jsonify({"message":refreshToken, "result":"success"})



@app.route('/getAccessToken', methods=['POST', 'OPTIONS'])
def getAccessToken():
    content = request.get_json(force=True)
    print(content)
    refreshToken = content['refreshToken']
    payload = jwt.decode(refreshToken,secret)
    print(payload['refreshSecret'])
    user = User.objects(refreshSecret=payload['refreshSecret'])

    if not user:
        print("fail")
        return jsonify({"message":"fail"})
    else:
        secs = int(time.time())
        accessToken = jwt.encode({'email': payload['email'], 'exp': secs + 360}, secret, algorithm='HS256')
        return accessToken




@app.route('/accessGroup', methods=['POST', 'OPTIONS'])
def accessGroupMethod():
    content=request.get_json()
    type = content['accessGroupType']
    if type == 'owner':
        if not AccessGroup.objects(name = content['accessGroupName']):
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
            access1.access = [Access(content['access']['control'], [Time(start=content['access']['time']['start'], stop=content['access']['time']['stop'])])]
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
                access1.access.index(Access(content['access']['control'], [Time(start=content['access']['time']['start'], stop=content['access']['time']['stop'])]))
                print("try")
            except:
                access1.access.append(Access(content['access']['control'], [Time(start=content['access']['time']['start'], stop=content['access']['time']['stop'])]))
                access1.save()

        return jsonify({"result":"success","message":"updated"})
    else:
        return jsonify({"result": "fail", "message": "Wrong access Group Type"})

'''
{"accessGroupName":"servants",
"accessGroupType":"other",
"UIDs":"hella@gmail.com",
"access":{"control":"light","time":{"start":"0900","stop":"0930"}}}
'''

@app.route('/displayControls', methods=['POST', 'OPTIONS'])
def displayControls():
    content = request.get_json()
    accessToken = content['accessToken']
    if check_auth(accessToken):
        type = current_user.accessGroupType
        email = payload['email']
        access_user = AccessGroup.objects.get(type=type,UIDs = email)
        print(access_user)
        return jsonify({"message": access_user.access, "result": "success"})
    else:
        return jsonify({"message": "UID and type not unique", "result": "fail"})

@app.route('/createControls', methods=['POST', 'OPTIONS'])
def createControlsMethods():
    content = request.get_json()
    try:
        cont = Controls.objects.get(group=content['group'])
    except:
        new = Controls(group=content['group'])
        new.rooms = [Rooms(content['room'], [
            Control(name=content['control']['name'], displayName=content['control']['displayName'],
                    controlStatus=content['control']['controlStatus'],
                    userFriendlyLog=[{content['timeStamp']: {'log': content['log']}}])])]
        new.save()
        return jsonify({"result": "success", "message": "control created"})

    for item in cont.rooms:
        if item['name'] == content['room']:
            break
        else:
            cont.rooms.append(Rooms(content['room'], [
                Control(name=content['control']['name'], displayName=content['control']['displayName'],
                        controlStatus=content['control']['controlStatus'],
                        userFriendlyLog=[{content['timeStamp']: {'log': content['log']}}])]))
            cont.save()
            return jsonify({'result': 'success', 'message': 'room added'})

    if [item]:
        for i in range(len(cont.rooms)):
            if cont.rooms[i] == item:
                break
        if [item for item in cont.rooms[i].controls if item['displayName'] == content['control']['displayName']]:
            print('inside controls if')
            return jsonify({'result': 'fail', 'message': 'room/control combination already exists'})
        else:
            print('inside controls else')
            cont.rooms[i].controls.append(Control(name=content['control']['name'], displayName=content['control']['displayName'], controlStatus=content['control']['controlStatus'], userFriendlyLog=[{content['timeStamp']: {'log': content['log']}}]))
            cont.save()
            return jsonify({'result':'success', 'message': 'control added'})
'''
{"group":"firstfloor",
"room":"terrace",
"control":{"controlStatus":"0",
"displayName":"socket2",
"name":"fridge"
},
"log":"fridge is off",
"timeStamp":"201824590425"}
'''










