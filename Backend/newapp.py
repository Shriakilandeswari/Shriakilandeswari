from flask import Flask,jsonify,request
from flask_sqlalchemy import SQLAlchemy 
from flask_bcrypt import Bcrypt
import validators
import re
from flask_security import roles_accepted,UserMixin, RoleMixin
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

class users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.relationship('role',secondary='userRole')
    report_to = db.Column(db.Integer, nullable=True) 

class role(db.Model, RoleMixin):
    __tablename__ = 'role'
    id = db.Column(db.Integer, primary_key=True) 
    name = db.Column(db.String(20), unique=True) 

class userRole(db.Model):
    __tablename__ = 'userRole'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))
    role_id = db.Column(db.Integer(), db.ForeignKey('role.id'))
   

@app.get("/")
def index():
    return "hello world"


@app.post("/user/addrole")
@jwt_required()
def addRole():
    user_id = get_jwt_identity()
    user = users.query.filter_by(id = user_id).first()
    user_role1 = userRole.query.filter_by(user_id = user.id).first()
    if user_role1.role_id == 1:
        name = request.json['name']
        newRole = role(name=name)
        db.session.add(newRole)
        db.session.commit()
        return jsonify({
            "message" : "New Role Created",
            "Role":{
                "role_name" : name
            }
        })


@app.patch("/users/<id>")

def patch_user(id):
    
    user = users.query.filter_by(id = id).first()
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


@app.get("/token/refresh")
@jwt_required(refresh=True)
def refresh_user_token():
    identity = get_jwt_identity()
    access = create_access_token(identity = identity)
    return jsonify({
        "access" : access
    })


@app.post("/user/adduser")
@jwt_required()
def addUser():

    user_id = get_jwt_identity()
    user = users.query.filter_by(id = user_id).first()
    user_role1 = userRole.query.filter_by(user_id = user.id).first()
    if user_role1.role_id == 1:
        username = request.json['username']
        email = request.json['email']
        password = request.json['password']
        roleid = request.json['roleid']
        report_to = request.json['report_to']

        if(username == "" or email == "" or password == ""):
            return jsonify({'error':'Please fill all the fields to register'})
        if len(username) < 3:
            return jsonify({'error':'Username is too short'})
        if users.query.filter_by(username=username).first() is not None:
            return jsonify({'error':'The username is aldready taken'})

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
        user1 = users(username=username,email=email,password=pwd_hash,report_to=report_to)
        role1 = role.query.filter_by(id = roleid).first()
        user1.role.append(role1)
        db.session.add(user1)
        db.session.commit()

        return jsonify({
            'message':"User created",
            'user' : {
                'username':username,'email':email,'password':pwd_hash,'report_to':report_to
            }
        })

    else:
        return jsonify({
            "error" : "You are not a valid user to access this page"
        })

   
@app.post("/signin")
def login():
    email = request.json['email']
    password = request.json['password']

    if(email == "" or password == ""):
        return jsonify({'error':'Please fill all the fields to login'})

    user = users.query.filter_by(email = email).first()
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


@app.get("/users")
def get_all_employee_details():
    all_users = users.query.all()
    output_users=[]
    for each_user in all_users:
        user_data = {}
        user_data['id'] = each_user.id
        user_data['username'] = each_user.username
        user_data['password'] = each_user.password
        
        user_data['reporting_to'] = each_user.report_to
        output_users.append(user_data)

    return jsonify({
        'users' : output_users
    })



@app.post("/change_role")
@jwt_required()
def change():
    user_id = get_jwt_identity()
    user = users.query.filter_by(id = user_id).first()
    user_role1 = userRole.query.filter_by(user_id = user.id).first()
    if user_role1.role_id == 1:
        
        userId = request.json['userId']
        user_role2 = users.query.filter_by(id = userId).first()
        if user_role2:
            roleid = request.json['roleid']
            role1 = role.query.filter_by(id = roleid).first()
            user_role2.role.append(role1)
            db.session.add(user_role2)
            db.session.commit()
            return jsonify({
            "message" : f"The user role is updated"
        })
        else:
            return jsonify({
                "error" : "Invalid user credentials"
            })
    else:
        return jsonify({
            "error" : "You are not a valid user to access this page"
        })


       
        

if __name__ == '__main__':
    app.app_context().push()
    db.create_all()
    app.run(debug=True)