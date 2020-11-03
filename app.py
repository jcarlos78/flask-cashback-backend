from itertools import product
from flask import Flask, request, jsonify, make_response
from flask import json
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from datetime import date, datetime
from werkzeug.datastructures import WWWAuthenticate
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import uuid
import jwt
import datetime

#TODO user blueprint for separating route to smaller files

def create_app(env_config):

    app = Flask(__name__)

    if env_config == 'testing':
        app.config.from_object("config.TestingConfig")
    elif app.config["ENV"] == "production":
        app.config.from_object("config.ProductionConfig")
    else:
        app.config.from_object("config.DevelopmentConfig")

    print(f'ENV is set to: {app.config["ENV"]}')

    db = SQLAlchemy(app)

    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        public_id = db.Column(db.String(50), unique=True)
        name = db.Column(db.String(50))
        email = db.Column(db.String(50), unique=True)
        cpf = db.Column(db.String(11), unique=True)
        password = db.Column(db.String(50)) 
        date_created = db.Column(db.DateTime, default=datetime.datetime.utcnow())
        admin = db.Column(db.Boolean)
        def init_db(self):
            db.init_app(app)
            db.app = app
            db.create_all()
            hashed_password = generate_password_hash('admin', method='sha256')
            new_user = User(
                public_id=str(uuid.uuid4()), 
                email='admin@admin.com',
                password=hashed_password,
                admin=True
            )
            db.session.add(new_user)
            db.session.commit()

    class Product(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        codigo = db.Column(db.String(50),nullable=False)
        price = db.Column(db.Float, nullable=False)
        cpf = db.Column(db.String(11), nullable=False)
        status = db.Column(db.String(50), nullable=False)
        date_created = db.Column(db.DateTime, default=datetime.datetime.utcnow())

    db.create_all()
    db.session.commit()        

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

#User API

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
        required={'WWW-Authenticate: Basic realm="Authentication required", charset="UTF-8"'}
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return make_response('Authentication failure', 401, required)
        user = User.query.filter_by(email=auth.username).first()
        if not user:
            return make_response('Authentication failure', 401, required)
        if check_password_hash(user.password, auth.password):
            access_token = jwt.encode({'public_id':user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
            return jsonify({'access_token': access_token.decode("utf-8")})
        return make_response('Authentication failure', 401, required)

# Products API

    @app.route('/product', methods=['POST'])
    @token_required
    def create_product(current_user):
        data = request.get_json()
        status = 'Aprovado' if current_user['cpf'] == '153.509.460-56' else 'Em validação'
        new_product = Product(
            codigo = data['codigo'],
            price = data['price'],
            cpf = current_user['cpf'],
            status = status
        )
        db.session.add(new_product)
        db.session.commit()
        return jsonify({'message': 'New product created!'})

    @app.route('/')
    def home():
        return jsonify({'message': 'api v1.0.0'})    

    return app