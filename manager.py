# This scripts handles all db migrations such as upgrading the db and so on
from app import app
from app import db
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager


migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)
app.debug = True  # activating flask debug mode

if __name__ == '__main__':
    manager.run()