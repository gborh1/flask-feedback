from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators, TextAreaField
from wtforms.validators import InputRequired, Email, EqualTo


class RegisterForm(FlaskForm):
    """Form for registering a user."""

    username = StringField("Username", validators=[InputRequired()])
    password = PasswordField("Password", validators=[InputRequired()])
    email = StringField("Email", validators=[
                        InputRequired(), Email()])
    first_name = StringField("First Name", validators=[InputRequired()])
    last_name = StringField("Last Name", validators=[InputRequired()])


class LoginForm(FlaskForm):
    """Form for registering a user."""

    username = StringField("Username", validators=[InputRequired()])
    password = PasswordField("Password", validators=[InputRequired()])


class FeedbackForm (FlaskForm):
    title = StringField("Title", validators=[InputRequired()])
    content = TextAreaField("Feedback Text", validators=[InputRequired()])


class EmailForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])


class ChangePassword(FlaskForm):
    password = PasswordField('New Password', [InputRequired(), EqualTo(
        'confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password')


class PasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired()])
