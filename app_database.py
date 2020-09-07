from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    username = db.Column(db.String(25), primary_key=True)
    password = db.Column(db.String(64))

class Files(db.Model):
    owner = db.Column(db.String(25), primary_key=True)
    file_name = db.Column(db.String(64), primary_key=True)
    public = db.Column(db.Boolean, primary_key=True)