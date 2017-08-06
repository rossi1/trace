import os

basdir = os.path.abspath(os.path.dirname(__file__))


class DevelopmentConfig:
    """This class contains
    configs of all flask extensions
    being used
    """
    DEBUG = True
    # flask_wtf configs
    WTF_CSRF_ENABLED = True  # this protects forms against cross-site forgery
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'  # generate a standard secret key and also Used to securely sign the token

    # sqlalchemy config using sqlite
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basdir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # RecaptchaField config

    RECAPTCHA_PUBLIC_KEY = '6LfFNysUAAAAAH8XvHjiSSpCpxrJc95vI-uN5Swy'
    RECAPTCHA_PRIVATE_KEY = os.environ.get('private key')  # this key should be kept secret

    # Mail Settings

    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_USE_TLS = True
    MAIL_PORT = 587
    MAIL_USERNAME = os.environ.get('username')
    MAIL_PASSWORD = os.environ.get('password')
    MAIL_DEFAULT_SENDER = 'myapp@app.com'

    SECURITY_PASSWORD_SALT = 'my_precious_two'  # used for the token

