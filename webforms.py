#Imports
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Email, EqualTo, Length
from wtforms.widgets import TextArea
from wtforms_validators import AlphaNumeric

#Login Form Class
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[Email()])
    password_hash = PasswordField("Password", validators=[DataRequired()])
    #recaptcha = RecaptchaField()
    submit = SubmitField("Login")

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(min=1, max=32, message="Name cannot exceed 32 characters long")])
    email = StringField("Email", validators=[Email()])
    password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo("password_hash2", message="Passwords do not match!"), Length(min=8, max=128, message="Password must be at least 8 characters long")])
    password_hash2 =PasswordField("Confirm Password", validators=[DataRequired()])
    #recaptcha = RecaptchaField()
    submit = SubmitField("Register")

class BlogForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    body = StringField("Body", widget=TextArea())
    submit = SubmitField("Post")

class TTSForm(FlaskForm):
    input = StringField("Input", validators=[DataRequired(), Length(max=20)])
    submit = SubmitField("Send")