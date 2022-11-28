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

@app.route('/shoppers', methods = ['GET'])
def shoppers_get():
    if 'application/json' not in request.accept_mimetypes:
        return 'Unsupported Media Type', 415
    data = {}
    args = request.args
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 5))
    limit_plus_one = limit + 1
    has_next = False
    url_root = request.url_root
    if request.method == 'GET':
        query = client.query(kind=constants.shoppers)
        number_shoppers = len(list(query.fetch()))
        query_iter = query.fetch(offset=offset, limit=limit_plus_one)
        page = next(query_iter.pages)
        results = list(page)
        if len(results) > limit:
            has_next = True
            results = results[:-1]
        next_cursor = query_iter.next_page_token
        for e in results:
            e["id"] = e.key.id
            e["self"] = url_root + 'shoppers/' + str(e.key.id)
            if "target" in e and e["target"] is not None:
                target_id = e["target"]["id"]
                target_key = client.key(constants.products, int(target_id))
                target_product = client.get(key=target_key)
                target_url = url_root + "products/" + str(target_id)
                shoppers_target = {
                    "id": target_key.key.id,
                    "self": target_url
                }
                e["target"] = shoppers_target
            next_url = url_root + "shoppers?limit=" + str(limit) + "&offset=" + str(offset + limit)
        data = {
            "results": results
        }
        if has_next:
            data["next"] = next_url
            data["location"] = str(offset) + "-" + str(offset + limit) + " of " + str(number_shoppers) + " total shoppers"

        return Response(json.dumps(data), status=200, mimetype='application/json')
    else:
        return ('Method not supported', 404)

@app.route('/shoppers/<id>', methods = ['GET'])
def shopper_get(id):
    url_root = request.url_root
    shopper_key = client.key(constants.shoppers, int(id))
    shopper = client.get(key=shopper_key)
    if not shopper:
        error = {"Error": "No shopper with this shopper_id exists"}
        return Response(json.dumps(error), status=404, mimetype='application/json')
    shopper["id"] = shopper.key.id
    shopper["self"] = url_root + 'shoppers/' + str(shopper.key.id)
    if 'application/json' in request.accept_mimetypes:
        return Response(json.dumps(shopper), status=200, mimetype='application/json')
    else:
        return 'Unsupported Media Type', 415

@app.route('/shoppers', methods = ['POST'])
def shopper_post():
    # Content-Type Checks
    if request.content_type != 'application/json':
        return 'Unsupported Media Type', 415
    # Accept Check
    if 'application/json' not in request.accept_mimetypes:
        return 'Not Acceptable', 406
    url_root = request.url_root
    if request.method == 'POST':
        content = request.get_json()
        if "name" not in content or "type" not in content or "cost_threshold" not in content or "status" not in content or "quantity" not in content:
            error = {"Error": "The request object is missing at least one of the required attributes"}
            return Response(json.dumps(error), status=400, mimetype='application/json')
        # check if 'name' exists
        if name_exists(content['name'], constants.shoppers):
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
                "cost_threshold": float(content["cost_threshold"]),
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
def shopper_put(id):
    url_root = request.url_root
    #Put must contain all properties or property will be overwritten with value of 'None'
    if request.content_type != 'application/json':
        return 'Unsupported Media Type', 415
    if 'application/json' not in request.accept_mimetypes:
        return 'Not Acceptable', 406
    shopper_key = client.key(constants.shoppers, int(id))
    shopper = client.get(key=shopper_key)
    if not shopper:
        error = {"Error": "No shopper with this shopper_id exists"}
        return Response(json.dumps(error), status=404, mimetype='application/json')
    content = request.get_json()
    if "name" not in content or "type" not in content or "cost_threshold" not in content or "status" not in content or "quantity" not in content:
        error = {"Error": "The request object is missing at least one of the required attributes"}
        return Response(json.dumps(error), status=400, mimetype='application/json')
    # check if 'name' exists
    if name_exists(content['name'], constants.shoppers):
        error = {"Error": "The name of this shopper already exists. The name needs to be unique"}
        return Response(json.dumps(error), status=403, mimetype='application/json')
    if not is_integer(content['quantity']):
        error = {"Error": "The quantity of the product in stock MUST be an Integer"}
        return Response(json.dumps(error), status=400, mimetype='application/json')
    if not is_integer(content['cost_threshold']):
        error = {"Error": "The cost threshold MUST be a floating point value"}
        return Response(json.dumps(error), status=400, mimetype='application/json')
    shopper.update(
        {
            "name": content["name"],
            "description": content["description"],
            "type": content["type"],
            "status": content["status"],
            "cost_threshold": float(content["cost_threshold"]),
            "quantity": int(content["quantity"]),
            "target": None
        }
    )
    client.put(shopper)
    shopper["self"] = url_root + 'shoppers/' + str(shopper.key.id)
    shopper["id"] = shopper.key.id
    res = make_response(jsonify(shopper))
    res.headers["Content-Type"] = "application/json"
    res.headers['Location'] = url_root + 'shoppers/' + str(shopper.key.id)
    res.status_code = 200
    return res

@app.route('/shoppers/<id>', methods = ['PATCH'])
def shopper_patch(id):
    url_root = request.url_root
    # Put must contain all properties or property will be overwritten with value of 'None'
    if request.content_type != 'application/json':
        return 'Unsupported Media Type', 415
    if 'application/json' not in request.accept_mimetypes:
        return 'Not Acceptable', 406
    shopper_key = client.key(constants.shoppers, int(id))
    shopper = client.get(key=shopper_key)
    if not shopper:
        error = {"Error": "No shopper with this shopper_id exists"}
        return Response(json.dumps(error), status=404, mimetype='application/json')
    content = request.get_json()
    if 'id' in content:
        error = {"Error": "The id cannot be modified"}
        return Response(json.dumps(error), status=400, mimetype='application/json')
    if 'name' in content:
        if name_exists(content['name']):
            error = {"Error": "The name of this shopper already exists. The name needs to be unique."}
            return Response(json.dumps(error), status=400, mimetype='application/json')
        shopper['name'] = content['name']
    if 'description' in content:
        shopper['description'] = content['description']
    if 'type' in content:
        shopper['type'] = content['type']
    if 'status' in content:
        shopper['status'] = content['status']
    if 'cost_threshold' in content:
        if not is_float(content['cost_threshold']):
            error = {"Error": "The cost_threshold MUST be a Floating Point value"}
            return(Response(json.dumps(error), status=400, mimetype='application/json'))
        shopper['cost_threshold'] = content['cost_threshold']
    if 'quantity' in content:
        if not is_float(content['quantity']):
            error = {"Error": "The quantity MUST be an Integer value"}
            return (Response(json.dumps(error), status=400, mimetype='application/json'))
        shopper['quantity'] = content['quantity']
    client.put(shopper)
    shopper['id'] = shopper.key.id
    shopper['self'] = url_root + 'shoppers/' + str(shopper.key.id)
    res = make_response(jsonify(shopper))
    res.headers["Content-Type"] = "application/json"
    res.headers['Location'] = url_root + 'shoppers/' + str(shopper.key.id)
    res.status_code = 200
    return res

@app.route('/shoppers/<id>', methods = ['DELETE'])
def shopper_delete(id):
    shopper_key = client.key(constants.shoppers, int(id))
    shopper = client.get(key=shopper_key)
    if not shopper:
        error = {"Error": "No shopper with this shopper_id exists"}
        return Response(json.dumps(error), status=404, mimetype='application/json')
    if request.method == 'DELETE':
        client.delete(shopper_key)
        return "", 204
    else:
        return 'Method Not Allowed', 405


'''
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

'''
# Shopper and Product Relationship Endpoints
'''
@app.route('/shoppers/<shopper_id>/products/<product_id>', methods = ['PUT', 'DELETE'])
def assign_remove_product_to_shopper():
    pass
'''



if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)