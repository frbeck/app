from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256 as sha256
from datetime import datetime

db = SQLAlchemy()


class UserModel(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(12), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                "username": x.username,
                "password": x.password
            }

        return {"users": [to_json(x) for x in UserModel.query.all()]}

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {"message": "{} row(s) deleted".format(num_rows_deleted)}
        except:
            return {"message": "Something went wrong."}


class RevokedTokenModel(db.Model):
    __tablename__ = "revoked_tokens"

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120))

    def add(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def is_jti_blocklisted(cls, jti):
        query = cls.query.filter_by(jti=jti).first()
        return bool(query)


class EventModel(db.Model):
    __tablename__ = "events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('UserModel', backref=db.backref('users', lazy=True))
    description = db.Column(db.String(500), nullable=False)
    link = db.Column(db.String(240), nullable=True)
    address = db.Column(db.String(500), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_id(cls, ident):
        def to_json(x):
            return {
                "id": x.id,
                "username": x.user.username,
                "user_id": x.user_id,
                "description": x.description,
                "link": x.link,
                "address": x.address
            }

        if type(ident) != int:
            return {"user": {}}

        event = cls.query.filter_by(id=ident).first()

        if not event:
            return {"user": {}}

        return {
            "user": {
                "id": event.id,
                "username": event.user.username,
                "user_id": event.user_id,
                "description": event.description,
                "link": event.link,
                "address": event.address
            }
        }


class ProfileModel(db.Model):
    __tablename__ = "profiles"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('UserModel', backref=db.backref('profiles', lazy=True))
    name = db.Column(db.String(120), nullable=False)
    bio = db.Column(db.String(500), nullable=True)
    picture = db.Column(db.String, nullable=True)
    username = db.Column(db.String(120), nullable=False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_id(cls, ident):

        if type(ident) != int:
            return {"user": {}}

        profile = cls.query.filter_by(user_id=ident).first()

        if not profile:
            return {"user": {}}

        return {
            "user": {
                "username": profile.user.username,
                "id": profile.id,
                "user_id": profile.user_id,
                "name": profile.name,
                "bio": profile.bio,
                "picture": profile.picture
            }
        }

    @classmethod
    def find_by_username(cls, ident):

        if type(ident) != str:
            return {"user": {}}

        profile = cls.query.filter_by(username=ident).first()

        if not profile:
            return {"user": {}}

        return {
            "user": {
                "username": profile.username,
                "id": profile.id,
                "user_id": profile.user_id,
                "name": profile.name,
                "bio": profile.bio,
                "picture": profile.picture
            }
        }

    @classmethod
    def update_row(cls, ident, new_profile):
        print(new_profile)
        profile = cls.query.filter_by(username=ident).first()
        profile.name = new_profile.get("name", profile.name)
        profile.bio = new_profile.get("bio", profile.bio)
        profile.picture = new_profile.get("picture", profile.picture)
        db.session.commit()


class BusinessProfileModel(db.Model):
    __tablename__ = "businessProfiles"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('UserModel', backref=db.backref('businessProfiles', lazy=True))
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(500), nullable=True)
    location = db.Column(db.String(500), nullable=True)
    link = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(120), nullable=True)
    tags = db.Column(db.String(120), nullable=True)
    picture = db.Column(db.String, nullable=True)
    verified = db.Column(db.Boolean, nullable=False)

    def save_to_db(self):
        print('here3')
        db.session.add(self)
        print('here4')
        db.session.commit()
        print('here5')

    @classmethod
    def find_by_id(cls, ident):

        if type(ident) != int:
            return {"business": {}}

        profile = cls.query.filter_by(id=ident, verified=True).first()

        if not profile:
            return {"business": {}}

        return {
            "business": {
                "id": profile.id,
                "user_id": profile.user_id,
                "name": profile.name,
                "description": profile.description,
                "location": profile.location,
                "link": profile.link,
                "phone": profile.phone,
                "tags": profile.tags,
                "picture": profile.picture,
                "verified": profile.verified
            }
        }

    @classmethod
    def get_all(cls):

        profile = cls.query.all()

        if not profile:
            return {"business": {}}

        profile_list = []
        for i in range(len(profile)):
            profile_list.append(
                {
                    "id": profile[i].id,
                    "user_id": profile[i].user_id,
                    "name": profile[i].name,
                    "description": profile[i].description,
                    "location": profile[i].location,
                    "link": profile[i].link,
                    "phone": profile[i].phone,
                    "tags": profile[i].tags,
                }
            )
        print(profile_list)
        return profile_list

    @classmethod
    def verify(cls, ident, verify):
        if type(ident) != int:
            return {"business": {}}
        profile = cls.query.filter_by(id=ident, verified=True if verify == 0 else False).first()
        profile.verified = False if verify == 0 else True
        db.session.commit()

    @classmethod
    def get_all_unverified(cls):

        profile = cls.query.filter_by(verfied=False).all()

        if not profile:
            return {"business": {}}

        profile_list = []
        for i in range(len(profile)):
            profile_list.append(
                {
                    "id": profile[i].id,
                    "user_id": profile[i].user_id,
                    "name": profile[i].name,
                    "description": profile[i].description,
                    "location": profile[i].location,
                    "link": profile[i].link,
                    "phone": profile[i].phone,
                    "tags": profile[i].tags,
                }
            )
        print(profile_list)
        return profile_list
