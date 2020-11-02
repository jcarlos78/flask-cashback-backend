from flask import Flask, request, jsonify, make_response
from flask import json
from flask_sqlalchemy import SQLAlchemy
from datetime import date, datetime
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
import base64

app = Flask(__name__)

app.config['SECRET_KEY'] = 'SECRET_HASH_KEY'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlight_proj'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50))
    cpf = db.Column(db.String(11))
    password = db.Column(db.String(50)) 
    date_created = db.Column(db.DateTime, default=datetime.datetime.utcnow())

@app.route('/user', methods=['GET'])
def get_all_users():

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['email'] = user.email
        user_data['cpf'] = user.cpf
        output.append(user_data)

    return jsonify({'users': output})

@app.route('/user/<public_id>', methods=['GET'])
def get_one_user(public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message":"No user found!"})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['email'] = user.email
    user_data['cpf'] = user.cpf

    return jsonify({'user':user_data})

@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    # if(not data['name']):

    new_user = User(
        public_id=str(uuid.uuid4()), 
        name=data['name'],
        email=data['email'],
        cpf=data['cpf'],
        password=hashed_password
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created!'})    

@app.route('/user/<public_id>', methods=['DELETE'])
def delete_user(public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message":"User not found!"})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User deleted!'})    

@app.route('/login')
def login():

    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Authentication failure', 401, {'WWW-Authenticate: Basic realm="Authentication required", charset="UTF-8"'})

    user = User.query.filter_by(email=auth.username).first()

    if not user:
        return make_response('Authentication failure', 401, {'WWW-Authenticate: Basic realm="Authentication required", charset="UTF-8"'})

    if check_password_hash(user.password, auth.password):
        access_token = jwt.encode({'public_id':user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        # return jsonify({'access_token', str(base64.b64encode(access_token).decode("utf-8"))})
        return jsonify({'access_token': access_token.decode("utf-8")})

    return make_response('Authentication failure', 401, {'WWW-Authenticate: Basic realm="Authentication required", charset="UTF-8"'})

@app.route('/')
def home():
    return '<h1>API - v1.0.0</h1>'    


def validate_cpf(cpf):
    ''' Expects a numeric-only CPF string. '''
    if len(cpf) < 11:
        return False    
    
    if cpf in [s * 11 for s in [str(n) for n in range(10)]]:
        return False
    
    calc = lambda t: int(t[1]) * (t[0] + 2)
    d1 = (sum(map(calc, enumerate(reversed(cpf[:-2])))) * 10) % 11
    d2 = (sum(map(calc, enumerate(reversed(cpf[:-1])))) * 10) % 11
    return str(d1) == cpf[-2] and str(d2) == cpf[-1]    