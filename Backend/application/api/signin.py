from flask import request,jsonify,Blueprint
from application import db,bcrypt
from flask_jwt_extended import create_access_token, create_refresh_token
from application.models import users

signin = Blueprint('signin', __name__)
signin.url_prefix = "/signin"

@signin.post("/")
def login():
    email = request.json['email']
    password = request.json['password']

    if(email == "" or password == ""):
        return jsonify({'error':'Please fill all the fields to login'}),401

    user = (users.query.filter_by(email = email).first())
    if user and bcrypt.check_password_hash(user.password, password):
        refresh = create_refresh_token(identity = user.id)
        access = create_access_token(identity = user.id)
        return ({
            'user':{
                'refresh' : refresh,
                'access' : access,
                'username' : user.username,
                'email' : user.email
            },
            "success":"Login successful"
        }),200
    return ({
            "error":"Login Unsuccessful. Please check username and password"
        }),401