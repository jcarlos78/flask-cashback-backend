from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import date, datetime
from werkzeug.security import generate_password_hash
import uuid
import datetime

# app = Flask(__name__)

# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlight_unit_1_0'

# db = SQLAlchemy(app)

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     public_id = db.Column(db.String(50), unique=True)
#     name = db.Column(db.String(50))
#     email = db.Column(db.String(50))
#     cpf = db.Column(db.String(11))
#     password = db.Column(db.String(50)) 
#     date_created = db.Column(db.DateTime, default=datetime.datetime.utcnow())
#     admin = db.Column(db.Boolean)


# @app.route('/user', methods=['POST'])
# def create_user():

#     hashed_password = generate_password_hash('admin', method='sha256')
#     new_user = User(
#         public_id=str(uuid.uuid4()), 
#         email='admin@admin.com',
#         password=hashed_password,
#         admin=True
#     )

#     db.session.add(new_user)
#     db.session.commit()

#     return jsonify({'message': 'Admin user created!'})