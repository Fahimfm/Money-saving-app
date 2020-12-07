from functools import wraps

from flask import Flask, jsonify, make_response, json
from flask.json import JSONEncoder
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask import request
import requests
from sqlalchemy import desc

file = "config.ini"
config = ConfigParser()
config.read(file)

app = Flask(__name__)

user = config['data']['user']
password = config['data']['password']
host = config['data']['host']
database = config['data']['database']

app.secret_key = "this_is_my_s_key"
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{user}:{password}@{host}/{database}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
migrate = Migrate(app, db)

authentication_host = ""
selection_process_host = ""

# -----------------------------------------------------------
# Functions
# -----------------------------------------------------------


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
            current_user_id = json_response['id']
        except Exception as e:
            print(e)
            return make_response(jsonify({'message': 'token is invalid'}), response.status_code)

        return f(current_user_id, *args, **kwargs)
    return decorator


# create new group
@app.route("/group/create", methods=['POST'])
@token_required
def create_new_group(current_user_id):

    if not request.is_json or request.get_data() is None:
        return make_response(jsonify({'message': 'ERROR:JSON is required'}), 400)
    request_json = request.get_json()

    group_creator = current_user_id  # the id of the group creator
    name = request_json.get('name')
    max_members = request_json.get('max_members')
    saving_goal = request_json.get('saving_goal')

    # TODO: check if the duration of the group will take more than 12 months

    if max_members > 12:
        return make_response(jsonify({'message': 'Maximum members in group can\'t be more than 12'}), 403)

    if check_if_group_name_exist(name):
        return make_response(jsonify({'message': 'Group name is already exist'}), 403)

    current_group = GroupMembers.get_group_where_member_is_currently_active(group_creator)
    if current_group:
        return make_response(jsonify({'message': 'You can\'t  create or join multiple groups'}), 403)

    new_group = Group(group_creator, name, max_members, saving_goal)
    new_group.save_to_db()

    # add creator to group_members table
    new_member = GroupMembers(new_group.id, group_creator)
    new_member.save_to_db()

    return make_response(jsonify(new_group), 200)


# Join existing group
@app.route('/group/member/create/<int:group_id>', methods=['POST'])
@token_required
def join_existing_group(current_user, group_id):
    group = Group.find_group_by_id(group_id)
    if not group:
        return make_response(jsonify({'message': 'Group not found'}), 404)

    if check_group_capacity(group):
        return make_response(jsonify({'message': 'Group reached the maximum members'}), 405)

    current_group = GroupMembers.get_group_where_member_is_currently_active(current_user)
    if current_group:
        return make_response(jsonify({'message': 'You have active group, can\'t join multiple groups'}), 404)

    new_member = GroupMembers(group_id, current_user)
    new_member.save_to_db()
    return make_response(jsonify({'message': 'New member added successfully'}), 200)


# check if group size is not reached yet
def check_group_capacity(group):
    if GroupMembers.count_group_members_in_group_by_group_id(group.id) >= group.max_members:
        return True
    return False


# check if group name is available
def check_if_group_name_exist(name):
    group = Group.find_group_by_name(name)
    if group:
        return True
    return False


@app.route('/group/member/current_group', methods=['GET'])
@token_required
def get_user_current_active_group(current_user):
    if not current_user:
        return make_response(jsonify({'message': 'User not found'}), 404)

    current_group = GroupMembers.get_group_where_member_is_currently_active(current_user)
    if not current_group:
        return make_response(jsonify({'message': 'You have no active group'}), 404)

    group = Group.find_group_by_id(current_group.group_id)
    if not group:
        return make_response(jsonify({'message': 'Group not found'}), 404)

    return make_response(jsonify(group), 200)


@app.route('/group/members/all/<int:group_id>', methods=['GET'])
@token_required
def get_all_group_members(current_user, group_id):
    if not current_user:
        return make_response(jsonify({'message': 'User not found'}), 404)

    members = GroupMembers.get_all_group_members_in_group_by_group_id(group_id)
    return make_response(jsonify(members), 200)


# Leave group
@app.route('/group/member/leave/<int:group_id>', methods=['DELETE', 'POST'])
@token_required
def leave_group(current_user, group_id):
    user_id = current_user
    if not user_id:
        return make_response(jsonify({'message': 'User not found'}), 404)

    group = Group.find_group_by_id(group_id)
    if not group:
        return make_response(jsonify({'message': 'Group not found'}), 404)

    group_member = GroupMembers.find_group_members_in_group(group_id, user_id)
    if not group_member:
        return make_response(jsonify({'message': 'user or group not found in group members'}), 404)

    if group.is_selection_started:
        return make_response(jsonify({'message': 'Selection is started you are not allowed to leave group'}), 403)

    group_member.remove_from_db()
    return make_response(jsonify({'message': 'member was removed from group'}), 200)


# search for group by name, size, target amount
@app.route('/group/find_matching', methods=['POST'])
@token_required
def search_for_matching_groups(current_user):
    if not current_user:
        return make_response(jsonify({'message': 'User not found'}), 404)

    # read data from request
    if not request.is_json or request.get_data() is None:
        return make_response(jsonify({'message': 'ERROR:JSON is required'}), 400)
    request_json = request.get_json()

    search_type = request_json.get("type")
    value = request_json.get('value')

    if not search_type or not value:
        return make_response(jsonify({'message': 'You need to specify at least one filter'}), 400)

    queryset = None
    if search_type == 'name':
        queryset = Group.query \
            .filter((Group.name.like('%'+value+'%'))
                    | (Group.name == value)
                    & (Group.is_selection_started == False)
                    ).all()
    if search_type == 'max_members':
        queryset = Group.query \
            .filter((Group.max_members == value)
                    & (Group.is_selection_started == False)
                    ).all()
    if search_type == 'saving_goal':
        queryset = Group.query \
            .filter((Group.saving_goal == value)
                    & (Group.is_selection_started == False)
                    ).all()
    if not queryset:
        return make_response(jsonify({'message': 'No matching results were found'}), 404)

    return make_response(jsonify(queryset), 200)


# start selection process
@app.route('/group/start_selection/<int:group_id>', methods=['POST'])
@token_required
def start_selection_process(current_user, group_id):
    if not current_user:
        return make_response(jsonify({'message': 'User not found'}), 404)

    group = Group.find_group_by_id(group_id)
    if not group:
        return make_response(jsonify({'message': 'Group not found'}), 404)

    if group.is_selection_started:
        return make_response(jsonify({'message': 'Selection is already started you can\'t started again'}), 403)

    # TODO: start selection without updating the is_selection_started and wait for all members acceptance
    #  and after that update the var (current implementation in wrong)
    group.is_selection_started = True
    group.save_to_db()

    # TODO: send request to @selection_process_host

    # Reference to group_members table
    # Get number of members the group has
    NrOfMembers = GroupMembers.count_group_members_in_group_by_group_id(group_id)
    # Get all  members' id's (I need only id's not other columns * needs to be modified)
    groupMembers = GroupMembers.find_group_members_in_group(group_id, current_user)
    # Create unique random numbers
    randomNumbers = list(range(1, NrOfMembers + 1))
    counter = 0
    # random.shuffle(randomNumbers)

    # while randomNumbers:
    #     newRow = SelectionOrder(group_id, groupMembers[counter],
    #     randomNumbers.pop(), datetime.now()) #date needs to be modified
    #     newRow.save_to_db()
    #     counter += counter
    for i in range(1, len(randomNumbers)):
        groupMembers[i].user_id

    return make_response(jsonify("started"), 200)


# -----------------------------------------------------------
# Extra function not required yet
# -----------------------------------------------------------


# delete existing group
def delete_group():
    return


# -----------------------------------------------------------
# Serialization
# -----------------------------------------------------------


class CustomJSONEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Group):
            return {
                'id': obj.id,
                'group_creator_id': obj.group_creator_id,
                'name': obj.name,
                'max_members': obj.max_members,
                'saving_goal': obj.saving_goal,
                'is_selection_started': obj.is_selection_started,
                'created_on': obj.created_on,
                'updated_on': obj.updated_on,
            }
        if isinstance(obj, GroupMembers):
            return {
                'id': obj.id,
                'group_id': obj.group_id,
                'user_id': obj.user_id,
                'is_active': obj.is_active,
                'created_on': obj.created_on,
                'updated_on': obj.updated_on,
            }
        return super(CustomJSONEncoder, self).default(obj)


app.json_encoder = CustomJSONEncoder


# -----------------------------------------------------------
# Classes
# -----------------------------------------------------------

# class SelectionOrder(db.Model):
#     __tablename__ = 'selection_order'
#     id = db.Column(db.Integer, primary_key=True)
#     group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
#     member_id = db.Column(db.Integer)  # foreignKey from group_members table
#     number_in_qu = db.Column(db.Integer)
#     collecting_date = db.Column(db.DateTime, server_default=db.func.now()) # needs to be modified
#     created_on = db.Column(db.DateTime, server_default=db.func.now())

#     # Method to save user to DB
#     def save_to_db(self):
#         db.session.add(self)
#         db.session.commit()

#     # Method to remove user from DB
#     def remove_from_db(self):
#         db.session.delete(self)
#         db.session.commit()

#     # Class method which finds group from DB by id
#     @classmethod
#     def find_group_by_id(cls, _id):
#         return cls.query.filter_by(id=_id).all()

#     def __init__(self, group_id, member_id, number_in_qu, collecting_date):
#         self.group_id = group_id
#         self.member_id = member_id
#         self.number_in_qu = number_in_qu
#         self.number_in_qu = number_in_qu

#     def __repr__(self):
#         return '<id:{} name:{}>'.format(self.id, self.name)


class Group(db.Model):
    __tablename__ = 'group'
    id = db.Column(db.Integer, primary_key=True)
    group_creator_id = db.Column(db.Integer)  # foreignKey from USER TABLE
    name = db.Column(db.String())
    max_members = db.Column(db.Integer)
    saving_goal = db.Column(db.Float)
    is_selection_started = db.Column(db.Boolean, default=False)
    created_on = db.Column(db.DateTime, server_default=db.func.now())
    updated_on = db.Column(db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())

    # Method to save user to DB
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    # Method to remove user from DB
    def remove_from_db(self):
        db.session.delete(self)
        db.session.commit()

    # Class method which finds group from DB by group name
    @classmethod
    def find_group_by_name(cls, group_name):
        return cls.query.filter_by(name=group_name).first()

    # Class method which finds group from DB by id
    @classmethod
    def find_group_by_id(cls, _id):
        return cls.query.filter_by(id=_id).first()

    def __init__(self, group_creator_id, name, max_members, saving_goal):
        self.group_creator_id = group_creator_id
        self.name = name
        self.max_members = max_members
        self.saving_goal = saving_goal

    def __repr__(self):
        return '<id:{} name:{}>'.format(self.id, self.name)


class GroupMembers(db.Model):
    __tablename__ = 'group_members'
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    user_id = db.Column(db.Integer)  # foreignKey from USER TABLE
    is_active = db.Column(db.Boolean, default=True)
    created_on = db.Column(db.DateTime, server_default=db.func.now())
    updated_on = db.Column(db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())

    # Method to save user to DB
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    # Method to remove user from DB
    def remove_from_db(self):
        db.session.delete(self)
        db.session.commit()

    # Class method which gets all group members by group id
    @classmethod
    def find_group_members_in_group(cls, group_id, user_id):
        return cls.query.filter_by(group_id=group_id, user_id=user_id).first()

    # Class method which finds the current number of users in a group by group id
    @classmethod
    def count_group_members_in_group_by_group_id(cls, group_id):
        return cls.query.filter_by(group_id=group_id).count()

    # Class method which gets all group members by group id
    @classmethod
    def get_all_group_members_in_group_by_group_id(cls, group_id):
        return cls.query.filter_by(group_id=group_id).all()

    # Class method which gets the group where user is active
    @classmethod
    def get_group_where_member_is_currently_active(cls, user_id):
        return cls.query.filter_by(user_id=user_id, is_active=True).first()

    def __init__(self, group_id, user_id):
        self.group_id = group_id
        self.user_id = user_id
        self.is_active = True

    def __repr__(self):
        return '<id:{} group:{} user:{}>'.format(self.id, self.group_id, self.user_id)


if __name__ == '__main__':
    db.create_all()
    app.run()
