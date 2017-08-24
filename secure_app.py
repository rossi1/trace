import base64
import hashlib
from app.models import ConnectApiDb


class SecureApp:
    def __init__(self, appname, public_key, secret_key):
        self.appname = appname
        self.public_key = public_key
        self.secret_key = secret_key

    def get_values(self):
       value =  ConnectApiDb.query.get(self.secret_key).first()
       return value

    def convert_values(self):
        values = base64.b64encode(self.appname)
        return values

    def __hash__(self):
        hs = hashlib.sha1(b'self.secret_key')
        return hs.hexdigest()

    def verify_api(self, methods):
        if self.__hash__() == methods:
            return 'permission granted'
        else:
            return 'bad request'


user = SecureApp(ConnectApiDb.app_name, ConnectApiDb.secret_key, ConnectApiDb.secret_key)
print(user.get_values())