from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from logreg.models import User


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(),Length(min=2,max=20)])
    email = StringField('Email', validators=[DataRequired(),Email()])
    password = PasswordField('Password',validators=[DataRequired(),Length(min=8,message="password too short")])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(),EqualTo('password',message="passwords dont match")])
    submit = SubmitField('Sign Up')

    def validate_username(self,username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a other one')
    
    def validate_email(self,email):
        email = User.query.filter_by(email=email.data).first()
        if email:
            raise ValidationError('That email is taken. Please choose a other one')

    def validate_password(self,password):
        lower, upper, specialchar, digit = 0, 0, 0, 0
        capitalalphabets="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        smallalphabets="abcdefghijklmnopqrstuvwxyz"
        specialchar="$@_"
        digits="0123456789"
        if (len(password.data) >= 8):
            for i in password.data:
                if (i in smallalphabets):
                    lower+=1           
                if (i in capitalalphabets):
                    upper+=1           
                if (i in digits):
                    digit+=1           
                if(i in specialchar):
                    specialchar+=1       
        if (lower<1 and upper<1 and specialchar<1 and digit<1 and lower+specialchar+upper+digit==len(password.data)):
            raise ValidationError("Invalid Password")
        


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(),Email()])
    password = PasswordField('Password',validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')