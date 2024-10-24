#Imports
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Email, EqualTo, Length

#Login Form Class
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[Email()])
    password_hash = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[Email()])
    password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo("password_hash2", message="Passwords do not match!")])
    password_hash2 =PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Register")