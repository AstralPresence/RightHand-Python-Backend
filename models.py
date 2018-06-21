
from app import db, mongo
from flask_mongoengine import BaseQuerySet
from flask_security import UserMixin,RoleMixin

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
    meta = { 'collection': 'access_group', 'queryset_class': BaseQuerySet}


class Role(db.Document, RoleMixin):
    name = db.StringField(max_length=255)

class User(db.Document,UserMixin):
    roles=db.ListField(db.ReferenceField(Role))
    email = db.StringField(max_length = 255, unique = True)
    accessGroupType = db.StringField(max_length=80)
    profilePicURL = db.StringField()
    name = db.StringField(max_length=150)
    refreshSecret = db.LongField()
    active = db.BooleanField(default=True)
    expiry = db.StringField(max_length = 12)
    meta = { 'collection': 'user', 'queryset_class': BaseQuerySet}

class Control(db.EmbeddedDocument):
    name = db.StringField()
    controlStatus = db.FloatField()
    displayName = db.StringField()
    userFriendlyLog = db.ListField()
    meta = { 'collection': 'controls', 'queryset_class': BaseQuerySet}

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

