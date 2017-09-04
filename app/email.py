from app import mail
from flask_mail import Message
from app import app


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr
