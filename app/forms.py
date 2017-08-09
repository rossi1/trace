from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, BooleanField, DateField, IntegerField
from wtforms.validators import DataRequired, EqualTo, Email, ValidationError, Length, Optional
from .models import User


class RegistrationForm(FlaskForm):
    """This class contains all the deta fields for the first form including validators"""
    full_name = StringField('Full Name',  validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired(), Length(min=5, max=10)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm_password',
                                                                             message='Password must match')])
    confirm_password = PasswordField('reenter password', validators=[DataRequired()])
    re_captcha = RecaptchaField()
    submit = SubmitField('Create account')

    def validate_email(self, field):
        """This method raises an error if the email is already in the db"""
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('This email already exist with an account')


    def validate_username(self, field):
        """This method raises an error if the username already exits in db"""
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('This Username is already taken')


class CompleteForm(FlaskForm):
    address = StringField('Address', validators=[DataRequired()])
    city = StringField('City', validators=[DataRequired()])
    state = StringField('State', validators=[DataRequired()])
    postal_code = IntegerField('Postal code', validators=[Optional()])
    phone_number = IntegerField('Phone number', validators={DataRequired()})
    date_of_birth = DateField('Date of birth', validators=[Optional()], format='%Y/%m/%d')
    accept_tos = BooleanField('Accept', default=False, validators=[DataRequired()])
    submit = SubmitField('Continue')


class LoginForm(FlaskForm):
    """This class holds the data fields for the login form"""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in', default=False)
    submit = SubmitField('Sign in')


class EmailForm(FlaskForm):
    """This class renders the forms for validating email for the recovering of password"""
    email = StringField('Email', validators=[DataRequired(), Email()])
    captcha = RecaptchaField()
    submit = SubmitField('submit')

    #  validating the email address
    def validate_email(self, field):
        if not User.query.filter_by(email=field.data).first():
            raise ValidationError('This Email does not exist with any account')


class PasswordForm(FlaskForm):
    """This class renders the forms for re setting passwords"""
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm_password',
                                                                             message='Password must match')])
    confirm_password = PasswordField('Confirm Password')
    submit = SubmitField('submit')
