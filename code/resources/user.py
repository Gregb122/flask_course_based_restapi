import hmac
from flask_restful import Resource, reqparse
from flask_jwt_extended import (
    get_jwt,
    get_jwt_identity, 
    jwt_required, 
    create_access_token, 
    create_refresh_token
)
from models.user import UserModel
from blocklist import BLOCKLIST

str_to_bytes = lambda s: s.encode("utf-8") if isinstance(s, str) else s
safe_str_cmp = lambda a, b: hmac.compare_digest(str_to_bytes(a), str_to_bytes(b))

_user_parser = reqparse.RequestParser()
_user_parser.add_argument('username',
                    type=str,
                    required=True,
                    help="This field cannot be blank."
                    )
_user_parser.add_argument('password',
                    type=str,
                    required=True,
                    help="This field cannot be blank."
                    )


class User(Resource):
    @classmethod
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {"message": "User not found"}, 404
        return user.json()
    
    @classmethod
    def delete(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {"message": "User not found"}, 404
        username = user.username
        user.delete_from_db()
        return {'message': 'User {} deleted'.format(username)}, 200


class UserRegister(Resource):
    def post(self):
        data = _user_parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {"message": "A user with that username already exists"}, 400

        user = UserModel(data['username'], data['password'])
        user.save_to_db()

        return {"message": "User created successfully."}, 201


class UserLogin(Resource):
    @classmethod
    def post(cls):
        data = _user_parser.parse_args()
        
        user = UserModel.find_by_username(data['username'])
        
        if user and safe_str_cmp(user.password, data['password']):
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            return{
                'access_token': access_token,
                'refresh_token': refresh_token
            }, 200
        
        return {'message': 'Invalid credentials'}, 401


class UserLogout(Resource):
    @jwt_required()
    def post(self):
        jti = get_jwt()['jti']
        BLOCKLIST.add(jti)
        return {'message': 'Successfully logged out'}


class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        return {'access_token': new_token}, 200