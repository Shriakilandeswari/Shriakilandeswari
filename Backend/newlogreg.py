from flask import Flask,jsonify,request
from flask_sqlalchemy import SQLAlchemy 
from flask_bcrypt import Bcrypt
import validators
import re
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, create_refresh_token, get_jwt_identity
import os
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv('DATABASE_URL')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

JWT_SECRET_KEY = os.getenv('key')
JWTManager(app)

class User(db.Model):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(340), nullable=False)

@app.get("/")
def index():
    return "hello world"

@app.post("/signup")
def register():
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']

    if(username == "" or email == "" or password == ""):
        return jsonify({'error':'Please fill all the fields to register'})
    if len(username) < 3:
        return jsonify({'error':'Username is too short'})
    if User.query.filter_by(username=username).first() is not None:
        return jsonify({'error':'The username is aldready taken'})


    if not validators.email(email):
        return jsonify({'error':'Email is not valid'})
    if User.query.filter_by(email=email).first() is not None:
        return jsonify({'error':"Email is aldready taken"})


    if len(password) < 8:
        return jsonify({'error':'Password is should not be less than 8 characters'})
    if not re.match("(?=.*?[A-Z])", password):
        return jsonify({'error':'Your password should have atleast 1 uppercase'})
    if not re.match("(?=.*?[a-z])", password):
        return jsonify({'error':'Your password should have atleast 1 lowercase'})
    if not re.match("(?=.*?[0-9])", password):
        return jsonify({'error':'Your password should have atleast 1 digit'})
    if not re.match("(?=.*?[#?!@$%^&*-])", password):
        return jsonify({'error':'Your password should have atleast 1 special character'})


    pwd_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(username=username,email=email,password=pwd_hash)
    db.session.add(user)
    db.session.commit()

    return jsonify({
        'message':"User created",
        'user' : {
            'username':username,'email':email,'password':pwd_hash
        }
    })


@app.post("/signin")
def login():
    email = request.json['email']
    password = request.json['password']

    if(email == "" or password == ""):
        return jsonify({'error':'Please fill all the fields to login'})

    user = User.query.filter_by(email = email).first()
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
        })
    return ({
            "error":"Login Unsuccessful. Please check username and password"
        })

@app.get("/dashboard")
@jwt_required()
def home():
    user_id = get_jwt_identity()

    user = User.query.filter_by(id = user_id).first()

    return jsonify({
        "username" : user.username,
        "email" : user.email
    })

@app.get("/token/refresh")
@jwt_required(refresh=True)
def refresh_user_token():
    identity = get_jwt_identity()
    access = create_access_token(identity = identity)
    return jsonify({
        "access" : access
    })

@app.put("/users/<id>")
@jwt_required()
def change_user_credentials(id):
    user_id = get_jwt_identity()
    user = User.query.filter_by(id = user_id).first()
    if user:
        user.username = request.json['username']
        user.email = request.json['email']
        user.password = bcrypt.generate_password_hash(request.json['password']).decode('utf-8')

        db.session.add(user)
        db.session.commit()

        return jsonify({
            "message" : f"The user {user.username} successfully updated"
        })
    else:
        return jsonify({
            "error" : "Invalid user credentials"
        })


@app.delete("/users/<id>")
@jwt_required()
def remove_user(id):
    user_id = get_jwt_identity()
    user = User.query.filter_by(id = user_id).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({
            "message" : f"The user {user.username} successfully deleted"
        })
    else:
        return jsonify({
            "error" : "Invalid user credentials"
        })

@app.patch("/users/<id>")
@jwt_required()
def patch_user(id):
    user_id = get_jwt_identity()
    user = User.query.filter_by(id = user_id).first()
    if user:

        if 'username' in request.json:
            user.username = request.json['username']
        if 'email' in request.json:
            user.email = request.json['email']
        if 'password' in request.json:
            user.password = bcrypt.generate_password_hash(request.json['password']).decode('utf-8')

        db.session.commit()
        return jsonify({
            "message" : f"The user {user.username} successfully updated"
        })
    else:
        return jsonify({
            "error" : "Invalid user credentials"
        })


if __name__ == '__main__':
    app.app_context().push()
    db.create_all()
    app.run(debug=True)
