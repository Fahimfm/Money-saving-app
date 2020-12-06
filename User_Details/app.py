import datetime
import json
from functools import wraps
from configparser import ConfigParser
import jwt
from flask import Flask, jsonify, request, Response, make_response
from flask_migrate import Migrate
from flask_ngrok import run_with_ngrok
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import stripe



file = "config.ini"
config = ConfigParser()
config.read(file)

app = Flask(__name__)
run_with_ngrok(app)
user = config['data']['user']
password = config['data']['password']
host = config['data']['host']
database = config['data']['database']

app.config['SECRET_KEY'] = 'this_is_a_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{user}:{password}@{host}/{database}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)


class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    password = db.Column(db.String(100))
    admin = db.Column(db.Boolean)
    manyUsers = db.relationship("UserInfo", backref="user")

    # Method to save user to DB
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    # Method to remove user from DB
    def remove_from_db(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def encode_auth_token(cls, user_id):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Decodes the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'

    # def __init__(self, public_id,name, password):
    #     self.public_id=public_id
    #     self.name=name
    #     self.password=password
    # def __repr__(self):
    #     return f"<Person {self.name}>"


class UserInfo(db.Model):
    __tablename__ = 'user_info'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    address = db.Column(db.String(100))
    iban = db.Column(db.String(100))
    full_name = db.Column(db.String(100))
    phone_number = db.Column(db.String(100))
    is_agreed = db.Column(db.Boolean)

    # Method to save user to DB
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    # Method to remove user from DB
    def remove_from_db(self):
        db.session.delete(self)
        db.session.commit()


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        headers = request.headers
        token = headers.get('Authorization')

        if not token:
            return make_response(jsonify({'message': 'a valid token is missing'}), 400)

        try:
            data = Users.decode_auth_token(token)
            current_user = Users.query.filter_by(id=data).first()
        except Exception as ex:
            print(ex)
            return make_response(jsonify({'message': 'token is invalid or'}), 401)

        return f(current_user, *args, **kwargs)
    return decorator


@app.route('/register', methods=['GET', 'POST'])
def signup_user():
    data = request.get_json()
    user = Users.query.filter_by(email=data["email"]).first()
    if user is None:
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = Users(email=data['email'], password=hashed_password, admin=False)
        new_user.save_to_db()
        userinfo = UserInfo(user=new_user, iban=data['iban'],
                            address=data['address'],
                            full_name=data['full_name'],
                            phone_number=data['phone_number'])
        userinfo.save_to_db()
        return Response("{'message':'Registered Successfully!'}", status=201, mimetype='application/json')
    return Response("{'message':'The username already exists!'}", status=403, mimetype='application/json')


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    data = request.get_json()
    # auth = request.authorization
    # if not auth or not auth.username or not auth.password:
    #     return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    user = Users.query.filter_by(email=data["email"]).first()
    if user is not None:
        password_check = check_password_hash(user.password, data["password"])
        if password_check is False:
            return Response("{'message':'Please make sure your username and password are correct.'}",
                            status=401,
                            mimetype='application/json')
        else:
            token = Users.encode_auth_token(user.id)
            return jsonify({'token': token.decode('UTF-8')})

    # if (check):
    #     token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() +
    #     datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    #     return jsonify({'token' : token.decode('UTF-8')})
    # else:
    #     return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})

    return Response("{'message':'Please make sure your username and password are correct.'}",
                    status=401,
                    mimetype='application/json')


@app.route('/users/get/user', methods=['GET'])
@token_required
def get_current_user(current_user):
    if current_user:
        return make_response(jsonify({"id": current_user.id}), 200)
    return make_response(jsonify({'message': 'ERROR: cant get current user'}), 403)


@app.route('/person', methods=['POST', 'GET'])
@token_required
def handle_persons():
    data = request.get_json()
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            new_person = Users(email=data['email'], password=data['password'])
            new_person.save_to_db()
            return {"message": f"User {new_person.email} has been created successfully."}
        else:
            return {"message": "The request payload is not in JSON format"}

    elif request.method == 'GET':
        person = Users.query.filter_by(email=data['email']).first()
        user_in = UserInfo.query.filter_by(person=person).all()
        results = [{
                "username": person.email,
                "full_name": result.full_name,
                "address": result.address
            } for result in user_in]

        return {"user": results}


@app.route('/user/delete', methods=['DELETE'])
@token_required
def delete_user():
    data = request.get_json()
    name = data["email"]
    send = {"message": name + " doesn't exist"}
    user = Users.query.filter_by(email=data["email"]).first()
    userinfo = UserInfo.query.filter_by(person=user).first()
    if user is not None:
        user.remove_from_db()
        userinfo.remove_from_db()
        return {"message": f"Person {user.email} successfully deleted."}
    return Response(json.dumps(send), status=400, mimetype='application/json')


@app.route('/user/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
@token_required
def handle_user(user_id):
    user = Users.query.get_or_404(user_id)

    if request.method == 'GET':
        response = {
            "username": user.email,
        }
        return {"message": "success", "user": response}

    elif request.method == 'PUT':
        data = request.get_json()
        user.email = data['email']
        user.save_to_db()
        return {"message": f"User {user.email} successfully updated"}

    elif request.method == 'DELETE':
        user.remove_from_db()
        return {"message": f"User {user.email} successfully deleted."}


if __name__ == '__main__':
    app.run()
