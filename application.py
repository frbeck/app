from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager
import config

app = Flask(__name__)
api = Api(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = config.SECRET_KEY

app.config['JWT_SECRET_KEY'] = config.JWT_SECRET_KEY

jwt = JWTManager(app)

import resources
from views import *
from models import db, RevokedTokenModel

db.init_app(app)

@app.before_first_request
def create_tables():
  db.create_all()

@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
  jti = jwt_payload["jti"]
  return RevokedTokenModel.is_jti_blocklisted(jti)

api.add_resource(resources.UserRegistration, '/registration')
api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.UserLogoutAccess, '/logout/access')
api.add_resource(resources.UserLogoutRefresh, '/logout/refresh')
api.add_resource(resources.TokenRefresh, '/token/refresh')
api.add_resource(resources.AllUsers, '/users')

api.add_resource(resources.EventResource, '/event')
api.add_resource(resources.ProfileResource, '/profile')


if __name__ == "__main__":
  app.run(debug=config.DEBUG)