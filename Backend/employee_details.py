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

class employees(db.Model):
    __tablename__ = 'employees'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(60), nullable=False)
    reporting_to = db.Column(db.Integer,db.ForeignKey('managers.id'))

class managers(db.Model):
    __tablename__ = 'managers'
    id = db.Column(db.Integer, primary_key=True) 
    username = db.Column(db.String(20), unique=True)
    email = db.Column(db.String(120), unique=True) 
    password = db.Column(db.String(120),nullable=False)
    relate = db.relationship('employees', backref='managers', lazy=True)

@app.get("/")
def index():
    return "hello world"

@app.post("/signin")
def login():
    email = request.json['email']
    password = request.json['password']
    role = request.json['role']

    if(email == "" or password == ""):
        return jsonify({'error':'Please fill all the fields to login'})

    user = (employees.query.filter_by(email = email).first() or managers.query.filter_by(email = email).first())
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


@app.post("/addUser")
@jwt_required()
def addUser():
    current_user_id = get_jwt_identity()
    admin = employees.query.filter_by(id=current_user_id).first()
    if admin.role == "Admin":
        username = request.json['username']
        email =  request.json['email']
        password = request.json['password']
        role = request.json['role']

        if(username == "" or email == "" or password == ""):
            return jsonify({'error':'Please fill all the fields to register'})
        if len(username) < 3:
            return jsonify({'error':'Username is too short'})
        if employees.query.filter_by(username=username).first() is not None or managers.query.filter_by(username=username).first() is not None:
            return jsonify({'error':'The username is aldready taken'})


        if not validators.email(email):
            return jsonify({'error':'Email is not valid'})
        if employees.query.filter_by(email=email).first() is not None or managers.query.filter_by(email=email).first() is not None:
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

        if role == 'Admin' or role == 'Employee':
            user = employees(username=username,email=email,password=pwd_hash,role=role)

        if role == 'Manager':
            user = managers(username=username,email=email,password=pwd_hash)

        db.session.add(user)
        db.session.commit()

        return jsonify({
            'message':"User created",
            'user' : {
                'username':username,'email':email,'password':pwd_hash
            }
        })

    else:
        return jsonify({
            'error' : "You are not a admin to access this page"
        })

@app.patch("/assignmanager")
@jwt_required()
def assignrole():
    current_user_id = get_jwt_identity()
    admin = employees.query.filter_by(id=current_user_id).first()
    if admin.role == "Admin":
        emp_id = request.json['empId']
        managerId = request.json['managerId']
        emp = employees.query.filter_by(id = emp_id).first()
        if  emp is not None:
            if managers.query.filter_by(id = managerId).first() is not None:
                print("Hi")
                emp.reporting_to = managerId
                db.session.commit()
                return jsonify({
                    "message" : "Employee updated"
                })
            else:
                return jsonify({
                    "message":"manager id is not found"
                })
        else:
            return jsonify({
                "message":"employee id is not found"
            })
            
    else:
        return jsonify({
            "error" : "You are not an admin to access this page"
        })
            
            
           
@app.route("/change_role",methods=['PUT'])
@jwt_required() 
def changeRole():
    current_user_id = get_jwt_identity()
    admin = employees.query.filter_by(id = current_user_id).first()
    if admin.role == "Admin":
        user_id = request.json["userId"]
        currentRole = request.json["currentRole"]
        changeRole = request.json["changeRole"]

        if(currentRole == 'Employee'):
            emp = employees.query.filter_by(id = user_id).first()
            if emp:
                emp_copied = employees(username=emp.username,email=emp.email,password=emp.password) 
                db.session.delete(emp)
                if changeRole == "Manager":
                    changed_user = managers(username=emp_copied.username,email=emp_copied.email,password=emp_copied.password)    
                    db.session.add(changed_user)
                    db.session.commit()
                    return jsonify({
                        "message" : "Role is changed to manager"
                    })
        if(currentRole == 'Manager'):
            emp = managers.query.filter_by(id = user_id).first()
            if emp:
                emp_copied = managers(username=emp.username,email=emp.email,password=emp.password) 
                db.session.delete(emp)
                if changeRole == "Employee" or changeRole == "Admin":
                    changed_user = employees(username=emp_copied.username,email=emp_copied.email,password=emp_copied.password,role=changeRole)    
                    db.session.add(changed_user)
                    db.session.commit()
                    return jsonify({
                        "message" : "Role is changed"
                    })

    else:
        return jsonify({
            "error" : "You are not an admin to access this page"
        })

@app.delete("/users")
@jwt_required()
def delete_user():
    current_user_id = get_jwt_identity()
    admin = employees.query.filter_by(id = current_user_id).first()
    if admin.role == "Admin":
        user_id = request.json['user_id']
        role = request.json['role']

        if role == 'Admin' or role == "Employee":
            user = employees.query.filter_by(id = user_id).first()
            if user:
                db.session.delete(user)
                db.session.commit()
                return jsonify({"message": "deleted successfully"})
            else:
                return jsonify({"error" : "No such user exists"})

        elif role == 'Manager':
            user = managers.query.filter_by(id = user_id).first()
            if user:
                db.session.delete(user)
                db.session.commit()
                return jsonify({"message": "deleted successfully"})
            else:
                return jsonify({"error" : "No such user exists"})
        else:
            return jsonify({"error": "No such role exists"})

    else:
        return jsonify({'msg': 'You do not have permission to access this route'})


@app.get('/view_individual')
@jwt_required()
def display():
    userId= request.json['user_id']
    role = request.json['role']
    
    if role == 'Employee' or role == "Admin":
        user = employees.query.filter_by(id = userId).first()
        if user:
            return jsonify({"username": user.username, "email":user.email, "reporting to": user.reporting_to})
        else:
            return jsonify({"error":"No Such user"})

    if role == 'Manager':
        manager = managers.query.filter_by(id = userId).first()
        if manager:
            return jsonify({"username": manager.username, "email": manager.email})
        else:
            return jsonify({"error":"No Such user"})

@app.get('/searchByName')
def searchByName():
        username = request.json['name']
        role = request.json['role']
        if role == 'Employee':
            user = db.session.query(employees).join(managers).filter(employees.reporting_to == managers.id).filter(employees.username == username).first()

            return jsonify({'id': user.id, 'username': user.username, 'email': user.email, "role": user.role, "reporting_to":user.managers.username})

        if role == 'Manager':
            manager = managers.query.filter_by(username = username).first()
            manager1 = []
            manager1.append({ 'username': manager.username, 'email': manager.email})
            reportee = employees.query.filter_by(reporting_to = manager.id).all()
            for report in reportee:
                manager1.append({'reportees': report.username})
            return jsonify(manager1)


@app.get('/searchByRole')
def searchByRole():
        role = request.json['role']
        persons = []
        if role == 'Employee':
           users = db.session.query(employees).join(managers).filter(employees.reporting_to == managers.id).all()
           print(users)
           for user in users:
                persons.append({'id': user.id, 'username': user.username, 'email': user.email, "reporting to": user.managers.username})
       
        elif role == 'Manager':
            results = managers.query.all()
            for Manager in results:
                persons.append({'id': Manager.id, 'manager_name': Manager.username, 'email': Manager.email})
        return jsonify(persons)

if __name__ == '__main__':
    app.app_context().push()
    db.create_all()
    app.run(debug=True)