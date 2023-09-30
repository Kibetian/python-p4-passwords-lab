from flask import request, session, jsonify
from flask_restful import Resource

from config import app, db, api
from models import User

class ClearSession(Resource):

    def delete(self):
        session['page_views'] = None
        session['user_id'] = None
        return {}, 204

class Signup(Resource):

    def post(self):
        json = request.get_json()

        # Check if the username and password are present in the JSON data
        if 'username' not in json or 'password' not in json:
            return {'message': 'Missing username or password'}, 400

        user = User(
            username=json['username'],
            password_hash=json['password']
        )
        db.session.add(user)
        db.session.commit()
        
        # Store the user's ID in the session object
        session['user_id'] = user.id

        return user.to_dict(), 201

class CheckSession(Resource):

    def get(self):
        if 'user_id' in session:
            user_id = session['user_id']
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200

        return {}, 204

class Login(Resource):

    def post(self):
        json = request.get_json()

        if 'username' not in json or 'password' not in json:
            return {'message': 'Missing username or password'}, 400

        user = User.query.filter_by(username=json['username']).first()

        if user and user.authenticate(json['password']):
            # Set the 'user_id' session variable when the user logs in
            session['user_id'] = user.id
            return user.to_dict(), 200

        return {'message': 'Invalid username or password'}, 401

class Logout(Resource):

    def delete(self):
        # Clear the 'user_id' session variable when the user logs out
        if 'user_id' in session:
            session.pop('user_id')
        return {}, 204

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
