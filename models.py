from app import db, mongo

class Time(db.EmbeddedDocument):
    start = db.IntField()
    stop = db.IntField()

class Access(db.EmbeddedDocument):
    control = db.StringField(unique = True)
    time = db.ListField(db.EmbeddedDocumentField(Time), default =[])

class AccessGroup(db.DynamicDocument):
    type = db.StringField(max_length = 10)
    name = db.StringField(max_length=80, unique = True)
    UIDs = db.ListField(db.StringField(), default=[])
    access = db.ListField(db.EmbeddedDocumentField(Access), default = [])


class User(db.DynamicDocument):
    email = db.StringField(max_length = 255, unique = True)
    accessGroupType = db.StringField(max_length=80)
    profilePicURL = db.StringField()
    name = db.StringField(max_length=150)
    refreshSecret = db.LongField()


class Control(db.EmbeddedDocument):
    name = db.StringField()
    controlStatus = db.FloatField()
    displayName = db.StringField()
    userFriendlyLog = db.ListField()

class Rooms(db.EmbeddedDocument):
    name = db.StringField()
    controls = db.ListField(db.EmbeddedDocumentField(Control))

class Controls(db.Document):
    group = db.StringField()
    rooms = db.ListField(db.EmbeddedDocumentField(Rooms))


'''
class Wifi(db.Document):
    ssid = db.StringField()
    password = db.StringField()

'''






