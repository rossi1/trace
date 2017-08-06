from flask import Flask
from config import DevelopmentConfig
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_login import LoginManager
from flask_mail import Mail
from flask_wtf import CSRFProtect

app = Flask(__name__)
app.config.from_object(DevelopmentConfig)

db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager(app)
mail = Mail(app)
csrf = CSRFProtect(app)
login_manager.login_view = 'login'
login_manager.session_protection = 'strong'  # session protection to help prevent your users’ sessions from being stolen.



from app import views, models
