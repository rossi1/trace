from itsdangerous import URLSafeTimedSerializer as Serializer
from app import app


def generate_confirmation_token(email):
    ts = Serializer(app.config['SECRET_KEY'])
    return ts.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=84600):
    ts = Serializer(app.config['SECRET_KEY'])

    try:
        email = ts.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)

    except:
        return False
    return email


