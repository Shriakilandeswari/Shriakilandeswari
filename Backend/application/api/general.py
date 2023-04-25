from flask import Blueprint, Response,request,jsonify
from application import db,bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, create_refresh_token, get_jwt_identity
from application.models import users

general = Blueprint('general', __name__)
general.url_prefix = "/general"

@general.route('/')
def index():
    return "general page"

@general.get('/basic-details-id')
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


@general.get('/name-role-search')
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

