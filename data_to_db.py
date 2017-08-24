from app.models import ConnectApiDb
from app import db
import os


def connect_to_db():
    public_key = '0061'
    secret_key = os.urandom(4)
    print(secret_key)
    user = ConnectApiDb(app_name='android', public_key=public_key, secret_key=secret_key)

    try:
        db.session.add(user)
        db.session.commit()

    except:
        db.session.rollback()


if __name__ == '__main__':
    connect_to_db()
