
from app import db
from flask_mongoengine import BaseQuerySet
from flask_security import UserMixin, RoleMixin

class AccessGroup(db.DynamicDocument):
    type = db.StringField(max_length=10)
    name = db.StringField(max_length=80, unique=True)
    UIDs = db.ListField(db.StringField(), default=[])
    meta = {'collection': 'access_group'}


class Role(db.Document, RoleMixin):
    name = db.StringField(max_length=255)

class User(db.Document,UserMixin):
    roles = db.ListField(db.ReferenceField(Role))
    email = db.StringField(max_length=255, unique=True)
    accessGroupType = db.StringField(max_length=80)
    #accessGroupName = db.StringField(max_length=80)
    profilePicURL = db.StringField()
    name = db.StringField(max_length=150)
    userValidity = db.StringField(max_length=12)
    refreshSecret = db.LongField()
    active = db.BooleanField(default=True)
    fingerID = db.LongField()
    password = db.StringField()
    meta = {'collection': 'users', 'queryset_class': BaseQuerySet}

class Control(db.EmbeddedDocument):
    name = db.StringField()
    controlStatus = db.FloatField()
    displayName = db.StringField()
    ip = db.StringField()
    userFriendlyLog = db.ListField()
    type = db.StringField()

class Rooms(db.EmbeddedDocument):
    name = db.StringField()
    controls = db.ListField(db.EmbeddedDocumentField(Control))

class Controls(db.Document):
    groupName = db.StringField()
    rooms = db.ListField(db.EmbeddedDocumentField(Rooms))
    meta = {'collection': 'controls', 'queryset_class': BaseQuerySet}

class ControlData(db.EmbeddedDocument):
    controlTopic = db.StringField()
    controlStatus = db.FloatField()

class Mode(db.Document):
    name = db.StringField()
    controlData = db.EmbeddedDocumentListField(ControlData)


class Wifi(db.Document):
    ssid = db.StringField()
    password = db.StringField()
    meta = {'max_documents': 1, 'max_size': 200}

