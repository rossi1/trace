from app import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin


@login_manager.user_loader
def user_loader(user_id):
    """ This sets the callback for reloading a user from the session. The
        function you set should take a user ID (a ``unicode``) and return a
        user object, or ``None`` if the user does not exist."""
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    """UserMixin, This provides default implementations for the methods that Flask-Login
   expects user objects to have."""

    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(60))
    username = db.Column(db.String(120), unique=True)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String)
    phone_number = db.Column(db.String)
    account_confirmed = db.Column(db.Boolean, default=False)
    date_of_birth = db.Column(db.DateTime)
    email_confirmed = db.Column(db.Boolean, default=False)
    phone_number_confirmed = db.Column(db.Boolean, default=False)
    users = db.relationship('Address', backref='user', lazy='dynamic')


    @property
    def password(self):
        raise AttributeError('password is not in readable format')

    @password.setter
    def password(self, plaintext):
        self.password_hash = generate_password_hash(plaintext)

    def verify_password(self, plaintext):
        if check_password_hash(self.password_hash, plaintext):
            return True
        return False

    def __repr__(self):
        """This method is used for debugging"""
        return 'Person {}'.format(self.username)


class Address(db.Model):
    __tablename__ = 'Address'
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(120))
    state = db.Column(db.String(120))
    country = db.Column(db.String(120))
    postal_code = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'))


    def __repr__(self):
        return 'Address {}'.format(self.address)
