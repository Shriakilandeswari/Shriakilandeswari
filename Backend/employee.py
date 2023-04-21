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

class users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(60), nullable=False)
    reporting_to = db.Column(db.Integer,db.ForeignKey('users.id'),nullable=True)


@app.get("/")
def index():
    return "hello world"


def get_current_user():
    user_id = get_jwt_identity()
    user = users.query.filter_by(id=user_id).first()
    return user

@app.patch("/users/<id>")
@jwt_required()
def patch_user(id):
    user_id = get_jwt_identity()
    user = users.query.filter_by(id = user_id).first()
    if user:
        if 'password' in request.json:
            user.password = bcrypt.generate_password_hash(request.json['password']).decode('utf-8')
        db.session.commit()
        return jsonify({
            "message" : f"The user {user.username} successfully updated"
        })
    else:
        return jsonify({
            "error" : "You are not a valid user to change the details"
        })


@app.post("/signin")
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


@app.post("/user-create")
@jwt_required()
def addUser():
    current_user = get_current_user()
    if current_user.role == "Admin":
        username = request.json['username']
        email =  request.json['email']
        password = request.json['password']
        role = request.json['role']
        reporting_to = request.json['reportingTo']
        if(username == "" or email == "" or password == ""):
            return jsonify({'error':'Please fill all the fields to add the user'})
        
        if not validators.email(email):
            return jsonify({'error':'Email is not valid'})
        if users.query.filter_by(email=email).first() is not None:
            return jsonify({'error':"Email is aldready taken"})

        pwd_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        if reporting_to:
            m = reporting_to
            manager = users.query.filter_by(id=m).first()
            if manager.role != 'Manager':
                return jsonify({'message':'The manager id is not found'}),404

        if role == 'Admin' or role == 'Employee' or role == 'Manager':
            user = users(username=username,email=email,password=pwd_hash,role=role,reporting_to=reporting_to)
            db.session.add(user)
            db.session.commit()

        return jsonify({
            'message':"User created",
            'user' : {
                'username':username,'email':email,'role':role,'reporting to':reporting_to
            }
        }),200

    else:
        return jsonify({
            'error' : "You are not a admin to access this page"
        }),403

@app.patch("/manager-assign")
@jwt_required()
def assignrole():
    current_user = get_current_user()
    if current_user.role == "Admin":
        userid = request.json['userId']
        managerid = request.json['managerId']
        user = users.query.filter_by(id = userid).first()
        if  user:
            manager = users.query.filter_by(id = managerid).first()
            if manager:
                if manager.role == 'Manager':
                    user.reporting_to = managerid
                    db.session.commit()
                    return jsonify({
                        "message" : "Employee updated"
                    }),200
                else:
                    return jsonify({
                        "error" : "The given Id is not  manager"
                    }),404
            else:
                return jsonify({
                    "message":"Id is not found"
                }),404
        else:
            return jsonify({
                "message":"employee id is not found"
            }),404
            
    else:
        return jsonify({
            "error" : "You are not an admin to access this page"
        }),403
            
            
           
@app.patch("/role-change")
@jwt_required() 
def changeRole():
    current_user= get_current_user()
    if current_user.role == "Admin":
        userid = request.json["userId"]
        changerole = request.json["changeRole"]

        user = users.query.filter_by(id = userid).first()
        if user:
            if changerole == 'Admin' or changerole == 'Manager' or changerole == 'Employee':
                if user.role == 'Manager' and changerole == 'Employee':
                    reportees = users.query.filter_by(reporting_to = user.id).all()
                    for reportee in reportees:
                        reportee.reporting_to = None

                    user.role = changerole
                    db.session.commit()
                    return jsonify({
                                "message" : "Role is changed"
                    }),200
            else:
                return jsonify({
                    'message' : 'Invalid role'
                }),400
            
        else:
            return jsonify({
                'message' : 'User not found'
            }),404
    else:
        return jsonify({
                'error' : 'You are not an admin to access this page'
            }),403

@app.delete("/users")
@jwt_required()
def delete_user():
    current_user = get_current_user()
    if current_user.role == "Admin":
        user_id = request.json['user_id']
        user = employees.query.filter_by(id = user_id).first()
        if user:
            if user.role == 'Manager':
                reportees = users.query.filter_by(reporting_to = user.id).all()
                for reportee in reportees:
                    reportee.reporting_to = None
            db.session.delete(user)
            db.session.commit()
            return jsonify({"message": "deleted successfully"}),200
        else:
            return jsonify({"error": "No such user exists"}),404
    else:
        return jsonify({'msg': 'You do not have permission to access this route'}),403


@app.get('/basic-details-id')
@jwt_required()
def display():
    userId= request.json['user_id']
    user = users.query.filter_by(id = userId).first()
    result = []
    results = []
    if user:
        manager = users.query.filter_by(id = user.reporting_to).first()
        if manager:
            result.append({'username':user.username,'email':user.email,'role':user.role,'reporting to':manager.username})
            if user.role == 'Manager':
                reportees = users.query.filter_by(reporting_to = user.id).all()
                for reportee in reportees:
                    results.append(reportee.username)
        else:
            result.append({'username':user.username,'email':user.email,'role':user.role,'reporting to':user.reporting_to})
            if user.role == 'Manager':
                reportees = users.query.filter_by(reporting_to = user.id).all()
                for reportee in reportees:
                    results.append(reportee.username)
        return jsonify({
            "Info" : result,
            "reportees list" : results
        }),200
    else:
        return jsonify({"error":"No Such user exists"}),403


@app.get('/name-role-search')
@jwt_required()
def search():
    if 'name' in request.json:
        username = request.json['name']
        all_users = users.query.filter_by(username = username).all()
        print(all_users)
        result = []
        results = []
        final = []
        if all_users:
            for user in all_users:
                manager = users.query.filter_by(id = user.reporting_to).first()
                if manager:
                    result.append({'username':user.username,'email':user.email,'role':user.role,'reporting to':manager.username})
                    if user.role == 'Manager':
                        reportees = users.query.filter_by(reporting_to = user.id).all()
                        for reportee in reportees:
                            results.append({"reportees":reportee.username})
                    final.append(result+results)
                    result = []
                    results = []
                else:
                    result.append({'username':user.username,'email':user.email,'role':user.role,'reporting to':user.reporting_to})
                    if user.role == 'Manager':
                        reportees = users.query.filter_by(reporting_to = user.id).all()
                        for reportee in reportees:
                            results.append({"reportees":reportee.username})
                    final.append(result+results)
                    result = []
                    results = []

            return jsonify(Info=final),200
        else:
            return jsonify({"error":"No Such user exists"}),404

    elif 'role' in request.json:
        role = request.json['role']
        if role == 'Admin' or role == 'Manager' or role == 'Employee':
            all_users = users.query.filter_by(role = role).all()
            results = []
            if all_users:
                for user in all_users:
                    manager = users.query.filter_by(id = user.reporting_to).first()
                    if manager:
                        results.append({'username':user.username,'email':user.email,'reporting to':manager.username})
                    else:
                        results.append({'username':user.username,'email':user.email,'reporting to':user.reporting_to})

                return jsonify(results),200
            else:
                return({"message" : "No user under this role"}),404
        else:
            return jsonify({
                "error":"No such role exists"
            }),404

if __name__ == '__main__':
    app.app_context().push()
    db.create_all()
    app.run(debug=True)