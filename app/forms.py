from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField
from wtforms.validators import DataRequired, EqualTo, Email, ValidationError, Length
from .models import User
from wtforms.fields import FormField


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


class TelephoneForm(FlaskForm):
    area_code = StringField('Area code', validators=[DataRequired()])
    country_code = StringField('Country code', validators=[DataRequired()])
    number = StringField('Number', validators=[DataRequired()])


class CompleteRegistrationForm(FlaskForm):
    address = StringField('Address', validators=[DataRequired()])
    state = StringField('State', validators=[DataRequired()])
    postal_code = StringField('Post code', validators=[DataRequired()])
    country = StringField('Country', validators=[DataRequired()])
    """ reused the TelephoneForm to encapsulate the common telephone entry instead of
      writing a custom field to handle the 3 sub-fields
    """
    phone_number = FormField(TelephoneForm)
    recaptha = RecaptchaField()
    submit = SubmitField('Create Account')


class LoginForm(FlaskForm):
    """This class holds the data fields for the login form"""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in', default=False)
    submit = SubmitField('Sign in')
