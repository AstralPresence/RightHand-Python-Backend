from app import db, mongo

class Controls(db.Document):
    name = db.StringField(max_length=80, unique = True)
    controlStatus = db.FloatField(min_value = 0 ,max_value = 1)
    control_id = db.StringField(max_length=20)

class Rooms(db.Document):
    name = db.StringField(max_length=80, unique =True)
    controls = db.ListField(db.ReferenceField(Controls), default=[])

class ControlsCollection(db.Document):
    group = db.StringField(max_length = 80, unique = True)
    rooms = db.ListField(db.ReferenceField(Rooms),default = [])

class Time(db.EmbeddedDocument):
    start = db.IntField()
    stop = db.IntField()

class Access(db.EmbeddedDocument):
    control = db.StringField(unique = True)
    time = db.ListField(db.EmbeddedDocumentField(Time), default =[])

class AccessGroup(db.Document):
    type = db.StringField(max_length = 10)
    name = db.StringField(max_length=80, unique = True)
    UIDs = db.ListField(db.StringField(), default=[])
    access = db.ListField(db.EmbeddedDocumentField(Access), default = [])


class User(db.Document):
    email = db.StringField(max_length = 255, unique = True)
    accessGroupType = db.StringField(max_length=80)
    accessGroupName = db.StringField(max_length=80)
    profilePicURL = db.StringField()
    name = db.StringField(max_length=150)
    refreshSecret = db.LongField()



'''
class Wifi(db.Document):
    ssid = db.StringField()
    password = db.StringField()

'''






