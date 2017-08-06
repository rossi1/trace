from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, BooleanField, DateField, RadioField
from wtforms.validators import DataRequired, EqualTo, Email, ValidationError, Length, Optional
from .models import User


class RegistrationForm(FlaskForm):
    """This class contains all the deta fields for the first form including validators"""
    full_name = StringField('Full Name',  validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired(), Length(min=5, max=10)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm_password', message='Password must match')])
    confirm_password = PasswordField('reenter password', validators=[DataRequired()])
    submit = SubmitField('Submit')


    def validate_email(self, field):
        """This method raises an error if the email is already in the db"""
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('This email already exist with an account')

    def validate_username(self, field):
        """This method raises an error if the username already exits in db"""
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('This Username is already taken')


class CompleteRegistrationForm(FlaskForm):
    address = StringField('Address', validators=[DataRequired()])
    city = StringField('City', validators=[DataRequired()])
    state = StringField('State', validators=[DataRequired()])
    postal_code = StringField('Postal code', validators=[Optional()])
    phone_number = StringField('Phone number', validators={DataRequired()})
    date_of_birth = DateField('Date of birth', validators=[Optional()], format='%Y/%m/%d')
    recaptha = RecaptchaField()
    accept_tos = BooleanField('Accept', default=False, validators=[DataRequired()])
    submit = SubmitField('Create Account')


class LoginForm(FlaskForm):
    """This class holds the data fields for the login form"""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in', default=False)
    submit = SubmitField('Sign in')


"""The following two forms belows handles the reset password recovery
"""


class EmailForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('submit')

    def validate_email(self, field):
        if not User.query.filter_by(email=field.data).first():
            raise ValidationError('This Email does not exist with any account')


class PasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm_password', message='Password must match')])
    confirm_password = PasswordField('Confirm Password')
    submit = SubmitField('submit')
