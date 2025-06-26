from models import db

def create_database(app):
    with app.app_context():
        db.create_all()
        print("База данных успешно создана!")