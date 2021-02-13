import time
import json
import random
import calendar
import datetime
import requests

from functools import wraps
from flask import Flask, make_response, jsonify
from flask_restful import Api, Resource
from configparser import ConfigParser
from flask_ngrok import run_with_ngrok
from flask_sqlalchemy import SQLAlchemy
from flask import request

app = Flask(__name__)
api = Api(app)
# run_with_ngrok(app)
file = "config.ini"
config = ConfigParser()
config.read(file)

user = config['data']['user']
password = config['data']['password']
host = config['data']['host']
database = config['data']['database']
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{user}:{password}@{host}/{database}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
db = SQLAlchemy(app)

groups_management_host = 'http://127.0.0.1:5000/'
authentication_host = 'http://127.0.0.1:5001/'
email_service_host = 'http://127.0.0.1:5002/'


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        headers = request.headers
        token = headers.get('Authorization')
        response = None

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            headers = {'Content-Type': 'application/json', 'Authorization': token}
            response = requests.get(authentication_host + "users/get/user", headers=headers)
            json_response = json.loads(response.content.decode('utf-8'))
        except Exception as e:
            print(response.status_code)
            return make_response(jsonify({'message': 'token is invalid'}), response.status_code)

        return f(*args, **kwargs)

    return decorator


@app.route('/', methods=['GET', 'POST'])
def home():
    return make_response(jsonify({'response': 'selection process service running'}), 200)


@app.route('/group_selection_order/<int:group_id>', methods=['GET'])
@token_required
def get_selection_order_for_group(group_id):
    selection_order = SelectionOrder.find_group_selection_order_by_group_id(group_id)
    if not selection_order:
        return make_response(jsonify({'message': 'not found'}), 404)

    results = [{
        'id': order.id,
        'group_id': order.group_id,
        'member_id': order.member_id,
        'number_in_qu': order.number_in_qu,
        'collecting_date': order.collecting_date,
        'order_in_queue_accepted': order.order_in_queue_accepted,
        'transaction_is_made': order.transaction_is_made
    } for order in selection_order]

    return make_response(jsonify(results), 200)


def send_emails_to_group_members(group_id):
    # send each member an e-mail with position, collection date, group number,
    # total participants, monthly payments and total to receive

    # send request to @email_service_host
    headers = request.headers
    token = headers.get('Authorization')
    header = {'Content-Type': 'application/json', 'Authorization': token}
    json_data = get_selection_order_for_group(group_id).json()

    requests.post(email_service_host + 'send_new_group_confirmation_mail/' + str(group_id), headers=header ,json=json_data)
    return make_response(jsonify("ok"), 200)


@app.route('/get/<int:group_id>', methods=['GET'])
def get_all_group_members(group_id):
    token = login_as_admin()
    header = {'Content-Type': 'application/json', 'Authorization': token}
    response = requests.get(groups_management_host + "group/members/all/" + str(group_id), headers=header)
    res = json.loads(response.content.decode('utf-8'))
    return res


def collect_money_from_group_members(group_members):
    for member in group_members:
        token = login_as_admin()
        header = {'Content-Type': 'application/json', 'Authorization': token}
        response = requests.get(groups_management_host + "collect_money/" + str(member['user_id']), headers=header)
        # TODO : if the response failed LOG the error and reschedule the transaction


def send_money_to_the_current_member_in_queue(current_member_id):
    token = login_as_admin()
    header = {'Content-Type': 'application/json', 'Authorization': token}
    response = requests.get(groups_management_host + "transfer_collected_money/" + str(current_member_id),
                            headers=header)
    # TODO : if the response failed LOG the error and reschedule the transaction otherwise:
    res = json.loads(response.content.decode('utf-8'))  # transaction object expected
    return res


def login_as_admin():
    email = "admin@admin.com"
    user_password = "123456"
    header = {'Content-Type': 'application/json'}
    req = requests.post(authentication_host + "login", headers=header,
                        json={'email': email, 'password': user_password})
    res = json.loads(req.content.decode('utf-8'))
    return res['token']



def add_months(sourcedate, months):
    month = sourcedate.month - 1 + months
    year = sourcedate.year + month // 12
    month = month % 12 + 1
    day = min(sourcedate.day, calendar.monthrange(year, month)[1])
    return datetime.date(year, month, day)


@app.route("/selection_order", methods=["POST"])
@token_required
def start_selection_process():
    if not request.is_json or request.get_data() is None:
        return make_response(jsonify({'message': 'ERROR:JSON is required'}), 400)
    request_json = request.get_json(force=True)
    members = request_json.get("members")
    group = request_json.get('group_id')

    group_members = []
    # put the json with member id's in a list
    for member in members:
        group_members.append(member['user_id'])

    # Get the total number of members the group has
    no_of_members = len(group_members)

    # Create unique random numbers
    random_numbers = list(range(1, no_of_members + 1))  # creates an ordered list
    random.shuffle(random_numbers)  # shuffles the ordered list

    # Represents the member's id POSITION in groupMembers
    counter = 0

    standard_date = datetime.date.today()

    while random_numbers:  # goes through all the members
        random_number = random_numbers.pop()
        collecting_date = 0
        collecting_date = standard_date
        collecting_date = add_months(collecting_date,
                                     random_number)  # puts the correct date according to queue position

        new_row = SelectionOrder(group,
                                 group_members[counter],
                                 random_number,  # removes a number from random numbers list
                                 collecting_date, True, False)

        new_row.save_to_db()
        counter = counter + 1  # continues to next member

    # send_emails_to_group_members(group)

    return make_response(jsonify({"message": "ok"}), 200)


class SelectionOrder(db.Model):
    __tablename__ = 'selection_order'
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer)
    member_id = db.Column(db.Integer)  # foreignKey from group_members table
    number_in_qu = db.Column(db.Integer)
    collecting_date = db.Column(db.DateTime)  # needs to be modified
    created_at = db.Column(db.DateTime, default=datetime.date.today)
    order_in_queue_accepted = db.Column(db.Boolean, default=True)
    transaction_is_made = db.Column(db.Boolean, default=False)

    # Method to save user to DB
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    # Method to remove user from DB
    def remove_from_db(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def find_group_selection_order_by_group_id(cls, _id):
        return cls.query.filter_by(group_id=_id).all()

    @classmethod
    #   find transaction that should be send today &
    #   has order_in_queue_accepted is TRUE & transaction_is_made = FALSE
    def find_all_selection_order_to_be_send(cls):
        today = datetime.date.today()
        return cls.query.filter_by(collecting_date=today,
                                   order_in_queue_accepted=True,
                                   transaction_is_made=False).all()

    def __init__(self, group_id, member_id, number_in_qu, collecting_date, order_in_queue_accepted, transaction_is_made):
        self.group_id = group_id
        self.member_id = member_id
        self.number_in_qu = number_in_qu
        self.collecting_date = collecting_date
        self.order_in_queue_accepted = order_in_queue_accepted
        self.transaction_is_made = transaction_is_made

    def __repr__(self):
        return '<id:{}>'.format(self.id)




if __name__ == '__main__':
    app.run()
