import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
setup_db(app)
CORS(app)


# ROUTES

@app.route('/drinks', methods=['GET'])
def get_drinks():
    drinks = Drink.query.all()
    print(drinks,'drinks');
    return jsonify({
        'success': True,
        'drinks': [drink.short() for drink in drinks]
    }), 200


@app.route('/drinks-detail', methods=['GET'])
@requires_auth('get:drinks-detail')
def get_drinks_detail(payload):
    drinks = Drink.query.all()
    return jsonify({
        'success': True,
        'drinks': [drink.long() for drink in drinks]
    }), 200


@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def create_drink(token):
    print(token,'token in /drinks psot')
    data = request.get_json()
    print(data, 'data in post drinks')
    if not data:
        return jsonify({
            'success': False,
            'error': "No data provided in request body."
        }), 400

    drink = Drink(title=data['title'], recipe=json.dumps(data['recipe']))
    drink.insert()
    return jsonify({
        'success': True,
        'drinks': [drink.long()]
    }), 200


@app.route('/drinks/<int:id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def update_drink(payload, id):
    drink = Drink.query.get(id)
    if not drink:
        abort(404)

    data = request.get_json()
    if 'title' in data:
        drink.title = data['title']
    if 'recipe' in data:
        drink.recipe = json.dumps(data['recipe'])

    drink.update()
    return jsonify({
        'success': True,
        'drinks': [drink.long()]
    }), 200


@app.route('/drinks/<int:id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drink(payload, id):
    drink = Drink.query.get(id)
    if not drink:
        abort(404)
    drink.delete()
    return jsonify({
        'success': True,
        'delete': id
    }), 200



# Error Handling
@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "resource not found"
    }), 404


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


if __name__ == "__main__":
    app.debug = True
    app.run()
