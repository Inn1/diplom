from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime



db = SQLAlchemy()

class User(db.Model, UserMixin):
    user_id = db.Column(db.Integer, primary_key=True)
    fio = db.Column(db.String(150), nullable=False)          # ФИО
    login = db.Column(db.String(80), unique=True, nullable=False)  # логин
    password = db.Column(db.String(200), nullable=False)      # пароль (хранить хеш!)
    role_id = db.Column(db.Integer, db.ForeignKey('role.role_id'), nullable=False)   
    role = db.relationship('Role', backref=db.backref('users', lazy=True))

    def set_password(self, password):
        self.password = generate_password_hash(password, method='pbkdf2:sha256')


    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    @property
    def id(self):
        return self.user_id


    def __repr__(self):
        return f'<User {self.fio}>'
    


class Role(db.Model):
    role_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
        

    def __repr__(self):
        return f'<Role {self.name}>'
    

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f"<Category {self.name}>"
    

class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    filepath = db.Column(db.String(300), nullable=False)
    text = db.Column(db.Text, nullable=False)

    # Добавляем поле для хеша текста
    text_hash = db.Column(db.String(64), unique=True, index=True)
    
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    category = db.relationship('Category', backref=db.backref('documents', lazy=True))

    # Добавляем связь с пользователем
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('documents', lazy=True))

    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Document {self.filename} Category: {self.category.name}  User: {self.user.fio} Date: {self.date_added}>"
    



class DocumentHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
    document = db.relationship('Document', backref=db.backref('history', lazy=True))
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('document_changes', lazy=True))
    
    changed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    old_text = db.Column(db.Text, nullable=True)
    new_text = db.Column(db.Text, nullable=True)
    
    # Можно добавить поле с описанием изменений, если нужно
    # change_description = db.Column(db.String(300), nullable=True)

    def __repr__(self):
        return f"<DocumentHistory doc_id={self.document_id} user_id={self.user_id} at={self.changed_at}>"