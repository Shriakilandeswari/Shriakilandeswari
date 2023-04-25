from flask import Flask
from flask_sqlalchemy import SQLAlchemy 
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
import os
from flask_bcrypt import Bcrypt

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv('DATABASE_URL')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
  
bcrypt = Bcrypt(app)

JWT_SECRET_KEY = os.getenv('key')
JWTManager(app)

from application.api.admin import admin
from application.api.general import general
from application.api.signin import signin

app.register_blueprint(admin, url_prefix=admin.url_prefix)
app.register_blueprint(general, url_prefix=general.url_prefix)
app.register_blueprint(signin, url_prefix=signin.url_prefix)

  