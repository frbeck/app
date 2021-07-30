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
    return cls.query.filter_by(username = username).first()

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

  id = db.Column(db.Integer, primary_key = True)
  jti = db.Column(db.String(120))

  def add(self):
    db.session.add(self)
    db.session.commit()

  @classmethod
  def is_jti_blocklisted(cls, jti):
    query = cls.query.filter_by(jti = jti).first()
    return bool(query)

class EventModel(db.Model):
  __tablename__ = "events"

  id = db.Column(db.Integer, primary_key = True)
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
      return { "user": {} }

    event = cls.query.filter_by(id= ident).first()

    if not event:
      return { "user": {} }

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
  id = db.Column(db.Integer, primary_key = True)
  name = db.Column(db.String(120), nullable=False)

  def save_to_db(self):
    print("here")
    db.session.add(self)
    db.session.commit()

  @classmethod
  def find_by_id(cls, ident):

    if type(ident) != int:
      return { "user": {} }

    profile = cls.query.filter_by(id=ident).first()

    if not profile:
      return { "user": {} }

    return {
      "user": {
        "id": profile.id,
        "user_id": profile.user_id,
        "description": profile.description,
        "link": profile.link,
        "address": profile.address
      }
    }
