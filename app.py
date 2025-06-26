from flask import Flask
from routes import main
from models import db, User, Role, Category, Document
from database_сreate import create_database
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from flask_migrate import Migrate
from flask_wtf import CSRFProtect


app = Flask(__name__)
app.config['SECRET_KEY'] = 'j[htyytysq gfhjkm]'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///doc.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


app.config['SESSION_COOKIE_SECURE'] = False  # для локальной разработки без HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # или 'Strict'


app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

# Создайте папку, если её нет
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)



app.config['TEMP_UPLOAD_FOLDER']  = os.path.join(os.getcwd(), 'temp_uploads')
os.makedirs(app.config['TEMP_UPLOAD_FOLDER'], exist_ok=True)
csrf = CSRFProtect(app)
db.init_app(app)
migrate = Migrate(app, db)
# Создаем базу данных
create_database(app)
# Регистрируем Blueprint
app.register_blueprint(main)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'main.login'  # имя функции для входа


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__ == '__main__':
    app.run(debug=True)