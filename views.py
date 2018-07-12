from app import app
from functools import wraps

from models import User, Role, AccessGroup, Controls, Rooms, Control, Mode, ControlData
from flask_security import MongoEngineUserDatastore, UserMixin, RoleMixin
from flask import request
from flask import jsonify, redirect, Response
import random
import datetime
import time
# from jose
import jwt
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


def checkValidity(timeStamp):
    currentDT = datetime.datetime.now()
    currentdt = currentDT.strftime("%Y%m%d%H%M")
    print(str(currentdt))
    if timeStamp < str(currentdt):
        return False  # expired
    else:
        return True   # valid


user_datastore = MongoEngineUserDatastore(db, User, Role)

def checkFingerAccess(id):
    try:
        user = user_datastore.find_user(fingerID=id)
        type = user.accessGroupType
        email = user.email
        print('try')
    except:
        print('except')
        return False

    if type == 'owner':
        return True
    else:
        control = 'groundFloor/livingRoom/doorlock'
        current_time = datetime.datetime.now()
        current_time = current_time.strftime("%H%M")
        j = 0
        access_group = AccessGroup.objects.get(type=type)
        for i in range(len(access_group.UIDs)):
            if access_group.UIDs[i] == email:
                for j in range(len(access_group.access)):
                    if access_group.access[j].control==control:
                       for k in range(len(access_group.access[j].time)):
                           if (access_group.access[j].time[k].start <= int(current_time)) and (access_group.access[j].time[k].stop >= int(current_time)):
                               print('found')
                               return True
                           else:
                               print('Time not found')
                               continue
                    else:
                        print('control not found')
                        continue
            else:
                continue
        print('end')
        return False


                    #USER MANAGEMENT
#Create User Endpoint
@app.route('/users/create', methods=['POST', 'OPTIONS'])
@requires_auth
def createUsersMethod():
    content = request.get_json()
    if user_datastore.find_user(email=content['email']):
        return jsonify({"result": "fail", "message": "email already exists"})
    else:
        refreshKey = random.getrandbits(32)
        user_datastore.create_user(email=content['email'], refreshSecret=refreshKey, userValidity=content['userValidity'],
                                   accessGroupType=content['accessGroupType'])
        return jsonify({"result": "success", "message": "user created"})


'''
{"email":"eve@gmail.com",
"accessGroupType":"other",
"userValidity":"201806012230"}
'''

#Get User Endpoint
@app.route('/users/get', methods=['GET', 'OPTIONS'])
@requires_auth
def getUsersMethod():
    if current_user.accessGroupType == 'owner':
        users = User.objects.count()
        user = User.objects()
        userName = []
        email = []
        accessGroupName = []
        accessGroupType = []
        data = []

        for i in range(users):
            userName.append(user[i].name)
            email.append(user[i].email)
            accessGroupType.append(user[i].accessGroupType)
            accessGroup = AccessGroup.objects()
            for j in range(AccessGroup.objects.count()):
                if accessGroup[j].type == accessGroupType[i]:
                    for k in range(len(accessGroup[j].UIDs)):
                        if accessGroup[j].UIDs[k] == email[i]:
                            accessGroupName.append(accessGroup[j].name)
                            break;
                    break;

            data.append({'username': userName[i], 'email': email[i], 'accessGroupType': accessGroupType[i], 'accessGroupName': accessGroup[j].name})
        return jsonify({'result': 'success', 'message': data})
    else:
        return jsonify({'result': 'fail', 'message': 'not a owner type'})

# Edit User Endpoint
@app.route('/users/edit', methods=['POST', 'OPTIONS'])
@requires_auth
def editUsersMethod():
    content = request.get_json()
    user = User.objects.get(email=content['email'])
    user.accessGroupType = content['accessGroupType']
    user.userValidity = content['userValidity']
    user.save()
    return jsonify({'result':'success', 'message': 'user editted'})
'''
{ "email": "adam@gmail.com",
  "accessGroupType":"other",                #new type
  "userValidity": "201807111620"
}
'''

# Delete User Endpoint
@app.route('/users/delete', methods=['POST', 'OPTIONS'])
@requires_auth
def deleteUsersMethod():
    content = request.get_json()
    if current_user.accessGroupType == 'owner':
        if user_datastore.find_user(email=content['email']):
            user_datastore.delete_user(email=content['email'])
            return jsonify({'result': 'success', 'message': 'user deleted'})
        else:
            return jsonify({'result': 'fail', 'message': 'user not found'})
    else:
        return jsonify({'result': 'fail', 'message': 'not owner type user'})

'''
{ "email" : "adam@gmail.com"}
'''

                    #ACCESS GROUP
#create group endpoint
@app.route('/accessGroup/create', methods=['POST', 'OPTIONS'])
@requires_auth
def accessGroupMethod():
    content = request.get_json(force=True)
    print(content)
    type = content['type']
    if type == 'owner':
        if not AccessGroup.objects(name=content['name']):
            access = AccessGroup(type=type, name=content['name'], UIDs=content['UIDs'])
            access.save()
            return jsonify({"result": "success", "message": "owner group created"})
        else:
            access = AccessGroup.objects.get(name=content['name'])
            for i in range(len(content['UIDs'])):
                try:
                    access.UIDs.index(content['UIDs'][i])
                    print('UID already exists')
                except:
                    access.UIDs.append(content['UIDs'][i])
                    access.save()
                    print('UID appended')
            return jsonify({"result": "success", "message": "owner group UIDs appended"})

    elif type == 'other':
        if not AccessGroup.objects(name=content['name']):
            access = AccessGroup(type=type, name=content['name'], UIDs=content['UIDs'])
            access.accessAllowed = []
            for i in range(len(content['accessAllowed'])):
                access.accessAllowed.timeRestriction = []
                print('time')
                for j in range(len(content['accessAllowed'][i]['timeRestriction'])):
                    access.accessAllowed.timeRestriction.append({'start': content['accessAllowed'][i]['timeRestriction'][j]['start'], 'end': content['accessAllowed'][i]['timeRestriction'][j]['end']})
                access.accessAllowed.append({'controlTopic': content['accessAllowed'][i]['controlTopic'], 'timeRestriction': access.accessAllowed.timeRestriction})
            access.save()
            return jsonify({"result": "success", "message": "group created"})

        else:
            access = AccessGroup.objects.get(name=content['name'])
            for i in range(len(content['UIDs'])):
                try:
                    access.UIDs.index(content['UIDs'][i])
                    print('UID already exists')
                except:
                    access.UIDs.append(content['UIDs'][i])
                    access.save()
                    print('UID appended')
            for i in range(len(content['accessAllowed'])):
                if next((item for item in access.accessAllowed if item["controlTopic"] == content['accessAllowed'][i]['controlTopic']), None) :
                    print('found2')
                    array = access.accessAllowed
                    for j in range(len(content['accessAllowed'][i]['timeRestriction'])):
                        print('time')
                        try:
                            array[i]['timeRestriction'].index(
                                {'start': content['accessAllowed'][i]['timeRestriction'][j]['start'],
                                 'end': content['accessAllowed'][i]['timeRestriction'][j]['end']})
                            print('found')
                        except:
                            array[i]['timeRestriction'].append(
                                {'start': content['accessAllowed'][i]['timeRestriction'][j]['start'],
                                 'end': content['accessAllowed'][i]['timeRestriction'][j]['end']})
                            print('appended')
                        access.accessAllowed = array
                        access.save()

                else:
                    access.accessAllowed.append({'controlTopic': content['accessAllowed'][i]['controlTopic'],
                                                 'timeRestriction': content['accessAllowed'][i]['timeRestriction']})
                    print('appended2')
                    access.save()

            return jsonify({"result": "success", "message": "updated"})
    else:
        return jsonify({"result": "fail", "message": "Wrong access Group Type"})


'''
{"name":"servants",
"type":"other",
"UIDs":["hella@gmail.com"],
"accessAllowed":[{"controlTopic":"light","timeRestriction":[{"start":"0900","end":"0930"}]}]}
'''

# Get Groups Endpoint
@app.route('/accessGroup/get', methods=['GET', 'OPTIONS'])
@requires_auth
def getAccessGroups():
    name = []
    controls=[]
    data=[]
    accessGroup = AccessGroup.objects()
    accessGroups = AccessGroup.objects.count()
    for i in range(accessGroups):
        if accessGroup[i].type == 'owner':
            name.append(accessGroup[i].name)
            data.append({'name':name[i]})
        elif accessGroup[i].type == 'other':
            name.append(accessGroup[i].name)
            controls.append(accessGroup[i].accessAllowed)
            data.append({'name':name[i], 'controls':controls[i]})
    return jsonify({'result':'success', 'message': data})

                    # AUTHORIZATION
#Login Endpoint
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
                                   accessGroupType=user['accessGroupType'], profilePicURL=user['profilePicURL'],
                                   fingerID=user['fingerID'])
        return jsonify({"message": refreshToken, "result": "success"})


#Access Token Endpoint
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


                    #CONTROLS
#Edit Control Endpoint
@app.route('/controls/edit', methods=['POST', 'OPTIONS'])
@requires_auth
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
            "displayName":"light",
              "name":"light1"
             }
}
'''

#Get Event Log
@app.route('/getEventLog/<timestamp>', methods=['GET', 'OPTIONS'])
def getEventLog(timestamp):
    print(timestamp)
    data = []
    group = []
    room = []
    control = []
    groups = Controls.objects.count()
    cont = (Controls.objects())
    for i in range(groups):
        group.append(cont[i].groupName)
        rooms = len(cont[i].rooms)
        for j in range(rooms):
            room.append(cont[i].rooms[j].name)
            controls = len(cont[i].rooms[j].controls)
            for k in range(controls):
                control.append(cont[i].rooms[j].controls[k].name)
                timestamps = len(cont[i].rooms[j].controls[k].userFriendlyLog)
                for l in range(timestamps):
                    objTimeStamp = cont[i].rooms[j].controls[k].userFriendlyLog[l].keys()[0] 
                    if (objTimeStamp >= int(timestamp)):
                        data.append({"id": group[i] + '/' + room[j] + '/' + control[k],
                                     "timeStamp": objTimeStamp ,
                                     "log": cont[i].rooms[j].controls[k].userFriendlyLog[l][objTimeStamp]['log']})
                    else:
                        continue

    print(data)
    return jsonify({"result": "success", "message": data})


#Get Controls Endpoint
@app.route('/controls/get', methods=['GET', 'OPTIONS'])
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
                type = []
                for k in range(controls):
                    controlName.append(cont[i].rooms[j].controls[k].name)
                    displayName.append(cont[i].rooms[j].controls[k].displayName)
                    status.append(cont[i].rooms[j].controls[k].controlStatus)
                    type.append(cont[i].rooms[j].controls[k].type)
                    data.append(
                        {'type': type[k], 'name': controlName[k], 'status': status[k], 'displayName': displayName[k],
                         'group': group[i], 'room': room[j]})

        print(data)

        return jsonify({"message": data, "result": "success"})

                    # GROUP MODES
# Create Mode Endpoint
@app.route('/mode/create', methods=['POST', 'OPTIONS'])
def modeCreateMethod():
    content = request.get_json()
    if Mode.objects(name=content['name']):
        mode=Mode.objects.get(name=content['name'])
        flag = 0
        for i in range(len(content['controlData'])):
            flag1 = 0
            flag2 = 0
            for item in mode.controlData:
                if item['controlTopic'] == content['controlData'][i]['controlTopic']:
                    flag1 = 1
                    if item['controlStatus'] != content['controlData'][i]['controlStatus']:
                        flag2 = 1
                        control_status = item['controlStatus']

            if flag1 == 0:
                mode.controlData.append(ControlData(controlTopic=content['controlData'][i]['controlTopic'],
                                                    controlStatus=content['controlData'][i]['controlStatus']))
                mode.save()
                flag = 1
            elif flag2 == 1:
                mode.controlData.remove(ControlData(controlTopic=content['controlData'][i]['controlTopic'],
                                                    controlStatus=control_status))

                mode.controlData.append(ControlData(controlTopic=content['controlData'][i]['controlTopic'],
                                                    controlStatus=content['controlData'][i]['controlStatus']))
                mode.save()
                flag = 1
        if flag == 0:
            return jsonify({'result': 'fail', 'message': 'mode already exists'})
        else:
            return jsonify({'result': 'success', 'message': 'mode control data appended'})
    else:
        mode = Mode(name=content['name'])
        mode.controlData=[]
        for i in range(len(content['controlData'])):
            control_data = ControlData(controlTopic=content['controlData'][i]['controlTopic'], controlStatus=content['controlData'][i]['controlStatus'])
            mode.controlData.append(control_data)
        mode.save()
        return jsonify({'result': 'success', 'message': 'mode Created'})

'''
{ "name": "night",
 "controlData":[{"controlTopic":"groundFloor/bedRoom/light", "controlStatus":0},
                {"controlTopic":"firstFloor/bedRoom/light", "controlStatus":1}]
}
'''

#Get Modes Endpoint
@app.route('/mode/get', methods=['GET', 'OPTIONS'])
def getModeMethod():
    mode= Mode.objects()
    name=[]
    controlData=[]
    data=[]
    for i in range(Mode.objects.count()):
        name.append(mode[i].name)
        controlData.append(mode[i].controlData)
        data.append({'name':name[i], 'controlData':controlData[i]})
    return jsonify({'result':'success', 'message':data})


