from flask import Blueprint, Response,request,jsonify
from application import db,bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, create_refresh_token, get_jwt_identity
from application.models import users
import validators

admin = Blueprint('admin', __name__)
admin.url_prefix = "/admin"

@admin.route('/')
def index():
    return "admin page"

def get_current_user():
    user_id = get_jwt_identity()
    user = users.query.filter_by(id=user_id).first()
    return user

@admin.post("/user-create")
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

@admin.patch("/manager-assign")
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
            
            
           
@admin.patch("/role-change")
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

@admin.delete("/user-remove")
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
