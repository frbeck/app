from flask_restful import Resource
from flask_restful import Resource, reqparse
from passlib.hash import pbkdf2_sha256 as sha256
import traceback

from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, get_jwt, get_jwt_identity)

# @jwt_refresh_token_required is now @jwt_required(refresh=True)
# Renamed get_raw_jwt() to get_jwt()
from sqlalchemy import Text

from models import UserModel, RevokedTokenModel, EventModel, ProfileModel, BusinessProfileModel

login_parser = reqparse.RequestParser()
login_parser.add_argument("username", help="This field cannot be blank", required=True)
login_parser.add_argument("password", help="This field cannot be blank", required=True)


class UserRegistration(Resource):
    def post(self):
        data = login_parser.parse_args()

        if UserModel.find_by_username(data["username"]):
            return {"message": "User {} already exists.".format(data["username"])}

        new_user = UserModel(
            username=data["username"],
            password=UserModel.generate_hash(data["password"])
        )

        try:
            new_user.save_to_db()
            access_token = create_access_token(identity=data["username"])
            refresh_token = create_refresh_token(identity=data["username"])
            return {
                "message": "User {} was created.".format(data["username"]),
                "access_token": access_token,
                "refresh_token": refresh_token
            }
        except:
            return {"message": "Something went wrong!"}, 500


class UserLogin(Resource):
    def post(self):
        data = login_parser.parse_args()

        curr_user = UserModel.find_by_username(data["username"])

        if not curr_user or not UserModel.verify_hash(data["password"], curr_user.password):
            return {"message": "Wrong credentials"}

        access_token = create_access_token(identity=data["username"])
        refresh_token = create_refresh_token(identity=data["username"])

        return {
            "message": "Logged in as {}".format(curr_user.username),
            "access_token": access_token,
            "refresh_token": refresh_token
        }


class UserLogoutAccess(Resource):
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {"message": "Access token has been revoked"}
        except:
            return {"message": "Something went wrong"}, 500


class UserLogoutRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        jti = get_jwt()["jti"]
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {"message": "Refresh token has been revoked"}
        except:
            return {"message": "Something went wrong"}, 500


class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        curr_user = get_jwt_identity()
        access_token = create_access_token(identity=curr_user)
        return {"access_token": access_token}


class AllUsers(Resource):
    def get(self):
        return UserModel.return_all()


event_parser = reqparse.RequestParser()
event_parser.add_argument("id", type=int, help="This field cannot be blank", required=True)
new_event_parser = reqparse.RequestParser()
new_event_parser.add_argument("description", help="This field cannot be blank", required=True)
new_event_parser.add_argument("link", help="This field cannot be blank", required=False)
new_event_parser.add_argument("address", help="This field cannot be blank", required=False)


class EventResource(Resource):
    def get(self):
        data = event_parser.parse_args()

        try:
            ident = int(data["id"])
            event = EventModel.find_by_id(ident)
            return event
        except:
            return {"message": "Something went wrong."}, 500

    @jwt_required()
    def post(self):
        data = new_event_parser.parse_args()
        username = get_jwt_identity()
        curr_user = UserModel.find_by_username(username)

        try:
            traceback.print_exc()
            event = EventModel(
                user=curr_user,
                description=data["description"],
                link=data["link"],
                address=data["address"]
            )

            event.save_to_db()

            return {"message": "Success. User {} created event {}".format(curr_user.username, event.id)}
        except:
            return {"message": "Something went run."}, 500


profile_parser = reqparse.RequestParser()
profile_parser.add_argument("username", type=str, help="This field cannot be blank", required=True)
new_profile_parser = reqparse.RequestParser()
new_profile_parser.add_argument("name", help="This field cannot be blank", required=True)
new_profile_parser.add_argument("bio", help="This field cannot be blank", required=False)
new_profile_parser.add_argument("picture", help="This field cannot be blank", required=False)


class ProfileResource(Resource):
    def get(self):
        data = profile_parser.parse_args()
        print('here1')

        try:
            print('here2')
            ident = data["username"]
            print('here3')

            profile = ProfileModel.find_by_username(ident)
            print(profile)
            return profile
        except:
            return {"message": "Something went run."}, 500

    @jwt_required()
    def post(self):
        data = new_profile_parser.parse_args()
        username = get_jwt_identity()
        curr_user = UserModel.find_by_username(username)
        print(curr_user.username)

        try:
            profile = ProfileModel(
                user=curr_user,
                username=curr_user.username,
                name=data["name"],
                bio=data["bio"],
                picture=data["picture"]
            )
            profile.save_to_db()

            return {"message": "Success. User {} created profile {}".format(curr_user.username, profile.id)}
        except:
            return {"message": "Something went wrong."}, 500

    @jwt_required()
    def patch(self):
        data = profile_parser.parse_args()
        ident = data["username"]
        updated_profile = new_profile_parser.parse_args()
        ProfileModel.update_row(ident, updated_profile)
        return {"message": "Success"}


business_profile_parser = reqparse.RequestParser()
business_profile_parser.add_argument("id", type=int, help="This field cannot be blank", required=True)
business_profile_parser.add_argument("verify", type=int, help="This field cannot be blank", required=False)
new_business_profile_parser = reqparse.RequestParser()
new_business_profile_parser.add_argument("name", help="This field cannot be blank", required=True)
new_business_profile_parser.add_argument("description", help="Must be a string", required=False)
new_business_profile_parser.add_argument("location", help="Must be a string", required=False)
new_business_profile_parser.add_argument("link", help="Must be a string", required=False)
new_business_profile_parser.add_argument("phone", help="Must be a string", required=False)
new_business_profile_parser.add_argument("tags", help="Must be a string", required=False)
new_business_profile_parser.add_argument("picture", help="Must be a string", required=False)


class BusinessProfileResource(Resource):
    def get(self):
        data = business_profile_parser.parse_args()
        try:
            ident = int(data["id"])
            if ident == 0:
                profile = BusinessProfileModel.get_all()
            elif ident == -1:
                profile = BusinessProfileModel.get_all_unverified()
            else:
                profile = BusinessProfileModel.find_by_id(ident)
            return profile
        except:
            return {"message": "Something went run."}, 500

    @jwt_required()
    def post(self):
        data = new_business_profile_parser.parse_args()
        username = get_jwt_identity()
        curr_user = UserModel.find_by_username(username)

        try:
            profile = BusinessProfileModel(
                user=curr_user,
                name=data["name"],
                description=data["description"],
                location=data["location"],
                link=data["link"],
                phone=data["phone"],
                tags=data["tags"],
                picture=data["picture"],
                verified=False
            )

            profile.save_to_db()

            return {"message": "Success. User {} created business profile {}".format(curr_user.username, profile.id)}
        except:
            return {"message": "Something went, wrong."}, 500

    @jwt_required()
    def patch(self):
        username = get_jwt_identity()
        curr_user = UserModel.find_by_username(username)
        data = business_profile_parser.parse_args()
        ident = int(data["id"])
        if curr_user.username == 'fran' and data["verify"] is not None:
            BusinessProfileModel.verify(ident, data["verify"])
            return {"message": "Admin {} verified business profile {}".format(curr_user.username, ident)}


