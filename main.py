import datetime
import flask
from json2html import json2html
from flask import Flask, jsonify, request, Response, make_response
from google.cloud import datastore
import json
import constants

client = datastore.Client()
app = Flask(__name__)

def name_exists(name, entity_kind):
    query = client.query(kind=entity_kind)
    query.add_filter('name', '=', name)
    results = list(query.fetch())
    if len(results) > 0:
        return True
    return False

def is_integer(n):
    try:
        float(n)
    except ValueError:
        return False
    else:
        return float(n).is_integer()

def is_float(n):
    try:
        float(n)
        return True
    except ValueError:
        return False

# Home Page - Documentation for API
@app.route('/')
def index():
    return "Please use one of possible resource endpoints /shoppers, /products or /sources"

@app.route('/shoppers/<id>', methods = ['GET'])
def shopper_get(id):
    pass

@app.route('/shoppers', methods = ['POST'])
def shopper_post():
    # Content-Type Checks
    if request.content_type != 'application/json':
        return 'Unsupported Media Type', 415
    # Accept Check
    if 'application/json' not in request.accept_mimetypes:
        return 'Not Acceptable', 406
    # Hw4 - Objective #1
    url_root = request.url_root
    if request.method == 'POST':
        content = request.get_json()
        if "name" not in content or "type" not in content:
            error = {"Error": "The request object is missing at least one of the required attributes"}
            return Response(json.dumps(error), status=400, mimetype='application/json')
        # check if 'name' exists
        if name_exists(content['name']):
            error = {"Error": "The name of this shopper already exists. The name needs to be unique"}
            return Response(json.dumps(error), status=403, mimetype='application/json')
        if not is_integer(content['quantity']):
            error = {"Error": "The quantity of the product in stock MUST be an Integer"}
            return Response(json.dumps(error), status=400, mimetype='application/json')
        if not is_integer(content['cost_threshold']):
            error = {"Error": "The cost threshold MUST be a floating point value"}
            return Response(json.dumps(error), status=400, mimetype='application/json')
        new_shopper = datastore.entity.Entity(key=client.key(constants.shoppers))
        new_shopper.update(
            {
                "name": content["name"],
                "description": content["description"],
                "type": content["type"],
                "status": content["status"],
                "cost_threshold": float(content["cost"]),
                "quantity": int(content["quantity"]),
                "target": None
            }
        )
        client.put(new_shopper)
        new_shopper["self"] = url_root + 'shoppers/' + str(new_shopper.key.id)
        new_shopper["id"] = new_shopper.key.id
        return Response(json.dumps(new_shopper), status=201, mimetype='application/json')
    else:
        return ('Method not supported', 404)

@app.route('/shoppers/<id>', methods = ['PUT'])
def shopper_put():
    pass

@app.route('/shoppers/<id>', methods = ['PATCH'])
def shopper_patch():
    pass

@app.route('/shoppers/<id>', methods = ['DELETE'])
def shopper_delete():
    pass

@app.route('/shoppers', methods = ['PUT', 'DELETE'])
def shoppers_put_delete():
    return 'Method Not Allowed', 405

# Product Endpoints
@app.route('/products/<id>', methods = ['GET'])
def product_get(id):
    pass

@app.route('/products', methods = ['POST'])
def product_post():
    # Content-Type Checks
    if request.content_type != 'application/json':
        return 'Unsupported Media Type', 415
    # Accept Check
    if 'application/json' not in request.accept_mimetypes:
        return 'Not Acceptable', 406
    # Hw4 - Objective #1
    url_root = request.url_root
    if request.method == 'POST':
        content = request.get_json()
        if "name" not in content or "type" not in content:
            error = {"Error": "The request object is missing at least one of the required attributes"}
            return Response(json.dumps(error), status=400, mimetype='application/json')
        # check if 'name' exists
        if name_exists(content['name']):
            error = {"Error": "The name of this shopper already exists. The name needs to be unique"}
            return Response(json.dumps(error), status=403, mimetype='application/json')
        if not is_integer(content['quantity']):
            error = {"Error": "The quantity of the product in stock MUST be an Integer"}
            return Response(json.dumps(error), status=400, mimetype='application/json')
        if not is_integer(content['cost_threshold']):
            error = {"Error": "The cost threshold MUST be a floating point value"}
            return Response(json.dumps(error), status=400, mimetype='application/json')
        new_shopper = datastore.entity.Entity(key=client.key(constants.shoppers))
        new_shopper.update(
            {
                "name": content["name"],
                "description": content["description"],
                "type": content["type"],
                "status": content["status"],
                "cost_threshold": float(content["cost"]),
                "quantity": int(content["quantity"]),
                "target": None
            }
        )
        client.put(new_shopper)
        new_shopper["self"] = url_root + 'shoppers/' + str(new_shopper.key.id)
        new_shopper["id"] = new_shopper.key.id
        return Response(json.dumps(new_shopper), status=201, mimetype='application/json')
    else:
        return ('Method not supported', 404)

@app.route('/products/<id>', methods = ['PUT'])
def product_put():
    pass

@app.route('/products/<id>', methods = ['PATCH'])
def product_patch():
    pass

@app.route('/products/<id>', methods = ['DELETE'])
def product_delete():
    pass

@app.route('/products', methods = ['PUT', 'DELETE'])
def products_put_delete():
    return 'Method Not Allowed', 405


# Shopper and Product Relationship Endpoints
@app.route('/shoppers/<shopper_id>/products/<product_id>', methods = ['PUT', 'DELETE'])
def assign_remove_product_to_shopper():
    pass


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)