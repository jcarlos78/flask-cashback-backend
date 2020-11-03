
def get_all_users(current_user):
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

def get_one_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message":"No user found!"})
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['email'] = user.email
    user_data['cpf'] = user.cpf
    return jsonify({'user':user_data})

def create_user(current_user):
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

def delete_user(current_user,public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message":"User not found!"})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted!'})    

#Products

def create_product(current_user):
    data = request.get_json()
    status = 'Aprovado' if data['cpf'] == '153.509.460-56' else 'Em validação'
    new_product = Product(
        public_id = str(uuid.uuid4()), 
        codigo = data['codigo'],
        price = data['price'],
        cpf = data['cpf'],
        status = status
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'New product created!'})

def get_all_products(current_user):
    products = Product.query.all()
    output = []
    for product in products:
        product_data = {}
        product_data['public_id'] = product.public_id
        product_data['name'] = product.codigo
        product_data['price'] = product.price
        product_data['cpf'] = product.cpf
        product_data['status'] = product.status
        product_data['date_created'] = product.date_created
        output.append(product_data)
    return jsonify({'products': output})

def delete_products(current_user,public_id):
    products = Product.query.all()
    output = []
    for product in products:
        product_data = {}
        product_data['codigo'] = product.codigo
        product_data['price'] = product.price
        product_data['status'] = product.status
        product_data['date_created'] = product.date_created
        product_data['cash_back_percentage'] = product.date_created
        output.append(product_data)
    return jsonify({'products': output})