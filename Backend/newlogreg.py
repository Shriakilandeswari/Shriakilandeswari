from flask import Flask,jsonify,request
from flask_sqlalchemy import SQLAlchemy 
from flask_bcrypt import Bcrypt
#from werkzeug.security import check_password_hash, generate_password_hash
import validators
import re
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, create_refresh_token, get_jwt_identity
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'

pg_user = "postgres"
pg_pwd = "password"
pg_port = "5432"
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://{username}:{password}@localhost:{port}/flasksql".format(username=pg_user, password=pg_pwd, port=pg_port)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
JWT_SECRET_KEY = 'JWT_SECRET_KEY'
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
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

@app.post("/register")
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


@app.post("/login")
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

@app.get("/home")
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

@app.put("/change the user credentials")
def change_user_credentials():
    user_id = get_jwt_identity()
    user = User.query.filter_by(id = user_id).first()
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']
    user = User(username=username,email=email,password=pwd_hash)

if __name__ == '__main__':
    app.app_context().push()
    db.create_all()
    app.run(debug=True)