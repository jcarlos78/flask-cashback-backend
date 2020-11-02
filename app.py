from flask import Flask, request, jsonify, make_response
from flask import json
from flask_sqlalchemy import SQLAlchemy
from datetime import date, datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
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
    admin = db.Column(db.Boolean)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message':'Access-token missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
             return jsonify({'message':'Invalid token!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated    

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
            return jsonify({'messsage','Permission denied!'})

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
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
            return jsonify({'messsage','Permission denied!'})

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
@token_required
def create_user(current_user):
    if not current_user.admin:
            return jsonify({'messsage','Permission denied!'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    #TODO -> validate email, cpf and minimum requirements for password
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
@token_required
def delete_user(current_user,public_id):
    if not current_user.admin:
            return jsonify({'messsage','Permission denied!'})

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