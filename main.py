import datetime
import constants
from google.cloud import datastore
from flask import Flask, request, jsonify, redirect, render_template, session, url_for, Response, make_response
import requests
import constants
from six.moves.urllib.request import urlopen
from jose import jwt
from urllib.parse import quote_plus
import json
from os import environ as env
from dotenv import load_dotenv, find_dotenv
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

client = datastore.Client()

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

client = datastore.Client()

LODGINGS = "lodgings"

# Update the values of the following 3 variables
CLIENT_ID = env.get("AUTH0_CLIENT_ID") #'qPAzQOPpYvIAN5vOxbDraOm2kVxDWXtB'
CLIENT_SECRET = env.get("AUTH0_CLIENT_SECRET") #'PsDxYEShTS7i5P2-_DcBzJ18gMlGrXvQ5MGWc2xcBRy1yZ5VpCJ5gIx3PMsDxSAa'
DOMAIN = env.get("AUTH0_DOMAIN") #'cs493-hw7-autho.us.auth0.com'
# Username-Password-Authentication

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)
# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

def has_valid_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        return False

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        return False
    if unverified_header["alg"] == "HS256":
        return False
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            return False
        except jwt.JWTClaimsError:
            return False
        except Exception:
            return False

        return True
    else:
        return False

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                             "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                             "No RSA key in JWKS"}, 401)

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

# Model Helpers
def remove_product_from_shopper(shopper, product_id):
    product_list = []
    for prod in shopper["products"]:
        if prod['id'] is not int(product_id):
            product_list.append(prod)
    shopper["products"] = product_list
    return shopper

def remove_source_from_product(product, source_id):
    source_list = []
    for source in product["sources"]:
        if source['id'] is not int(source_id):
            source_list.append(source)
    product["sources"] = source_list
    return product

def delete_a_product(id):
    product_key = client.key(constants.products, int(id))
    product = client.get(key=product_key)
    for source in product['sources']:
        source_key = client.key(constants.sources, int(source['id']))
        client.delete(source_key)
    client.delete(product_key)

def add_user_filter(query, payload):
    user_id = payload["sub"]
    query.add_filter('user', '=', user_id)

def add_new_user(user_info):
    new_user = datastore.entity.Entity(key=client.key(constants.users))
    new_user.update({
        "uuid": user_info["sub"],
        "email": user_info["email"],
        "name": user_info["name"],
        "picture": user_info["picture"]
    })
    client.put(new_user)
    return new_user

# Home Page, Register, Login, Logout, Callback
@app.route('/')
def index():
    return render_template("index.html",
                           session=session.get("user"),
                           pretty=json.dumps(session.get("user")["token"], indent=4))

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    user_info = token["userinfo"]
    session["user"] = {
        "uuid": user_info["sub"],
        "token": token
    }
    # Check user entity, add user if currently does not exist.
    query = client.query(kind=constants.users)
    query.add_filter('uuid', '=', user_info["sub"])
    user_list = list(query.fetch())
    if len(user_list) == 0:
        user = add_new_user(user_info)
    return redirect("/")

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/register")
def register():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True),
        screen_hint="signup"
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("index", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login_user():
    username = request.form["username"]
    password = request.form["password"]
    body = {'grant_type': 'password', 'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type': 'application/json'}

# Users
@app.route('/users', methods = ['GET'])
def users_get():
    if request.method == "GET":
        url_root = request.url_root
        query = client.query(kind=constants.users)
        if 'application/json' not in request.accept_mimetypes:
            error = {"Error": "Unsupported Media Type"}
            return Response(json.dumps(error), status=415, mimetype='application/json')
        data = {}
        args = request.args
        offset = int(args.get('offset', 0))
        limit = int(args.get('limit', 5))
        limit_plus_one = limit + 1
        has_next = False
        if request.method == 'GET':
            number_users = len(list(query.fetch()))
            query_iter = query.fetch(offset=offset, limit=limit_plus_one)
            page = next(query_iter.pages)
            results = list(page)
            if len(results) > limit:
                has_next = True
                results = results[:-1]
            next_cursor = query_iter.next_page_token
            for e in results:
                e["id"] = e.key.id
                next_url = url_root + "users?limit=" + str(limit) + "&offset=" + str(offset + limit)
            data = {
                "results": results
            }
            if has_next:
                data["next"] = next_url
            data["index"] = str(offset + 1) + "-" + str(len(results)) + " of " + str(number_users) + " total users"

            return Response(json.dumps(data), status=200, mimetype='application/json')
    else:
        error = {"Error": "Method Not Allowed"}
        return Response(json.dumps(error), status=405, mimetype='application/json')

# Product - Operations
@app.route('/shoppers', methods = ['GET'])
def shoppers_get():
    valid_token = has_valid_jwt(request)
    url_root = request.url_root
    query = client.query(kind=constants.shoppers)
    if valid_token:
        payload = verify_jwt(request)
        add_user_filter(query, payload) # verify this successfully filters the results
    if 'application/json' not in request.accept_mimetypes:
        error = {"Error": "Unsupported Media Type"}
        return Response(json.dumps(error), status=415, mimetype='application/json')
    data = {}
    args = request.args
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 5))
    limit_plus_one = limit + 1
    has_next = False
    if request.method == 'GET':
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
        data["index"] = str(offset + 1) + "-" + str(len(results)) + " of " + str(number_shoppers) + " total shoppers"

        return Response(json.dumps(data), status=200, mimetype='application/json')
    else:
        return ('Method not supported', 404)

@app.route('/shoppers/<id>', methods = ['GET'])
def shopper_get(id):
    payload = verify_jwt(request)
    user_id = payload["sub"]
    url_root = request.url_root
    shopper_key = client.key(constants.shoppers, int(id))
    shopper = client.get(key=shopper_key)
    if not shopper:
        error = {"Error": "No shopper with this shopper_id exists"}
        return Response(json.dumps(error), status=404, mimetype='application/json')
    if "user" not in shopper or user_id != shopper["user"]:
        error = {"Error": "Not authorized to access this shopper"}
        return Response(json.dumps(error), status=403, mimetype='application/json')
    shopper["id"] = shopper.key.id
    shopper["self"] = url_root + 'shoppers/' + str(shopper.key.id)
    if 'application/json' in request.accept_mimetypes:
        return Response(json.dumps(shopper), status=200, mimetype='application/json')
    else:
        error = {"Error": "Unsupported Media Type"}
        return Response(json.dumps(error), status=415, mimetype='application/json')

@app.route('/shoppers', methods = ['POST'])
def shopper_post():
    payload = verify_jwt(request)
    # Content-Type Checks
    if request.content_type != 'application/json':
        error = {"Error": "Unsupported Media Type"}
        return Response(json.dumps(error), status=415, mimetype='application/json')
    # Accept Check
    if 'application/json' not in request.accept_mimetypes:
        error = {"Error": "Not Acceptable"}
        return Response(json.dumps(error), status=406, mimetype='application/json')
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
                "user": payload["sub"],
                "products": None
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
    payload = verify_jwt(request)
    if request.content_type != 'application/json':
        error = {"Error": "Unsupported Media Type"}
        return Response(json.dumps(error), status=415, mimetype='application/json')
    # Accept Check
    if 'application/json' not in request.accept_mimetypes:
        error = {"Error": "Not Acceptable"}
        return Response(json.dumps(error), status=406, mimetype='application/json')
    user_id = payload["sub"]
    url_root = request.url_root
    shopper_key = client.key(constants.shoppers, int(id))
    shopper = client.get(key=shopper_key)
    if not shopper:
        error = {"Error": "No shopper with this shopper_id exists"}
        return Response(json.dumps(error), status=404, mimetype='application/json')
    if "user" not in shopper or user_id != shopper["user"]:
        error = {"Error": "Not authorized to access this shopper"}
        return Response(json.dumps(error), status=403, mimetype='application/json')
    url_root = request.url_root
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
    if name_exists(content['name'], constants.shoppers) and content["name"] != shopper["name"]:
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
            "products": None,
            "user": payload["sub"]
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
    # Verify Token
    payload = verify_jwt(request)
    # Verify acceptable content
    if request.content_type != 'application/json':
        error = {"Error": "Unsupported Media Type"}
        return Response(json.dumps(error), status=415, mimetype='application/json')
    # Accept Check
    if 'application/json' not in request.accept_mimetypes:
        error = {"Error": "Not Acceptable"}
        return Response(json.dumps(error), status=406, mimetype='application/json')
    shopper_key = client.key(constants.shoppers, int(id))
    shopper = client.get(key=shopper_key)
    if not shopper:
        error = {"Error": "No shopper with this shopper_id exists"}
        return Response(json.dumps(error), status=404, mimetype='application/json')
    content = request.get_json()
    user_id = payload["sub"]
    if "user" not in shopper or user_id != shopper["user"]:
        error = {"Error": "Not authorized to access this shopper"}
        return Response(json.dumps(error), status=403, mimetype='application/json')
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
    # Verify Token
    payload = verify_jwt(request)
    shopper_key = client.key(constants.shoppers, int(id))
    shopper = client.get(key=shopper_key)
    if "user" not in shopper or payload["sub"] != shopper["user"]:
        error = {"Error": "Not authorized to access this shopper"}
        return Response(json.dumps(error), status=403, mimetype='application/json')
    if not shopper:
        error = {"Error": "No shopper with this shopper_id exists"}
        return Response(json.dumps(error), status=404, mimetype='application/json')
    if shopper['products'] is None:
        pass
    elif len(shopper['products']) > 0:
        for product in shopper['products']:
            delete_a_product(product['id'])
    client.delete(shopper_key)
    return "", 204

# Product - Operations
@app.route('/products', methods = ['GET'])
def products_get():
    valid_token = has_valid_jwt(request)
    url_root = request.url_root
    query = client.query(kind=constants.products)
    if valid_token:
        payload = verify_jwt(request)
        add_user_filter(query, payload) # verify this successfully filters the results
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
        number_products = len(list(query.fetch()))
        query_iter = query.fetch(offset=offset, limit=limit_plus_one)
        page = next(query_iter.pages)
        results = list(page)
        if len(results) > limit:
            has_next = True
            results = results[:-1]
        next_cursor = query_iter.next_page_token
        for e in results:
            e["id"] = e.key.id
            e["self"] = url_root + 'products/' + str(e.key.id)
            if "target" in e and e["target"] is not None:
                target_id = e["target"]["id"]
                target_key = client.key(constants.products, int(target_id))
                target_product = client.get(key=target_key)
                target_url = url_root + "products/" + str(target_id)
                products_target = {
                    "id": target_key.key.id,
                    "self": target_url
                }
                e["target"] = products_target
            next_url = url_root + "products?limit=" + str(limit) + "&offset=" + str(offset + limit)
        data = {
            "results": results
        }
        if has_next:
            data["next"] = next_url
        data["index"] = str(offset + 1) + "-" + str(len(results)) + " of " + str(number_products) + " total products"

        return Response(json.dumps(data, default=str), status=200, mimetype='application/json')
    else:
        return ('Method not supported', 404)

@app.route('/products/<id>', methods = ['GET'])
def product_get(id):
    payload = verify_jwt(request)
    user_id = payload["sub"]
    url_root = request.url_root
    product_key = client.key(constants.products, int(id))
    product = client.get(key=product_key)
    if not product:
        error = {"Error": "No product with this product_id exists"}
        return Response(json.dumps(error), status=404, mimetype='application/json')
    if "user" not in product or user_id != product["user"]:
        error = {"Error": "Not authorized to access this product"}
        return Response(json.dumps(error), status=403, mimetype='application/json')
    product["id"] = product.key.id
    product["self"] = url_root + 'products/' + str(product.key.id)
    if 'application/json' in request.accept_mimetypes:
        return Response(json.dumps(product, default=str), status=200, mimetype='application/json')
    else:
        return 'Unsupported Media Type', 415

@app.route('/products', methods = ['POST'])
def product_post():
    payload = verify_jwt(request)
    # Content-Type Checks
    if request.content_type != 'application/json':
        error = {"Error": "Unsupported Media Type"}
        return Response(json.dumps(error), status=415, mimetype='application/json')
    # Accept Check
    if 'application/json' not in request.accept_mimetypes:
        error = {"Error": "Not Acceptable"}
        return Response(json.dumps(error), status=406, mimetype='application/json')
    url_root = request.url_root
    if request.method == 'POST':
        content = request.get_json()
        if "name" not in content or "manufacturer" not in content or "type" not in content \
            or "availability" not in content:
            error = {"Error": "The request object is missing at least one of the required attributes"}
            return Response(json.dumps(error), status=400, mimetype='application/json')
        new_product = datastore.entity.Entity(key=client.key(constants.products))
        new_product.update(
            {
                "name": content["name"],
                "description": content["description"],
                "type": content["type"].lower(),
                "manufacturer": content["manufacturer"],
                "last_update": datetime.datetime.utcnow(),
                "availability": content["availability"],
                "recent_min_cost": 0.00,
                "recent_avg_cost": 0.00,
                "recent_max_cost": 0.00,
                "shopper": None,
                "user": payload["sub"]
            }
        )
        client.put(new_product)
        new_product["self"] = url_root + 'products/' + str(new_product.key.id)
        new_product["id"] = new_product.key.id
        return Response(json.dumps(new_product, default=str), status=201, mimetype='application/json')


@app.route('/products/<id>', methods=['PUT'])
def product_put(id):
    payload = verify_jwt(request)
    # Content-Type Checks
    if request.content_type != 'application/json':
        error = {"Error": "Unsupported Media Type"}
        return Response(json.dumps(error), status=415, mimetype='application/json')
    # Accept Check
    if 'application/json' not in request.accept_mimetypes:
        error = {"Error": "Not Acceptable"}
        return Response(json.dumps(error), status=406, mimetype='application/json')
    url_root = request.url_root
    product_key = client.key(constants.products, int(id))
    product = client.get(key=product_key)
    user_id = payload["sub"]
    if "user" not in product or user_id != product["user"]:
        error = {"Error": "Not authorized to access this shopper"}
        return Response(json.dumps(error), status=403, mimetype='application/json')
    content = request.get_json()
    if "name" not in content or "manufacturer" not in content or "type" not in content \
        or "availability" not in content or "recent_min_cost" not in content or "recent_avg_cost" not in content or "recent_max_cost" not in content:
        error = {"Error": "The request object is missing at least one of the required attributes"}
        return Response(json.dumps(error), status=400, mimetype='application/json')
    if not product:
        error = {"Error": "No product with this product_id exists"}
        return Response(json.dumps(error), status=404, mimetype='application/json')
    # check if 'name' exists
    if not is_float(content['recent_min_cost']):
        error = {"Error": "The recent_min_cost of the product in stock MUST be an floating point value"}
        return Response(json.dumps(error), status=400, mimetype='application/json')
    if not is_float(content['recent_max_cost']):
        error = {"Error": "The recent_max_cost of the product in stock MUST be an floating point value"}
        return Response(json.dumps(error), status=400, mimetype='application/json')
    if not is_float(content['recent_avg_cost']):
        error = {"Error": "The recent_avg_cost of the product in stock MUST be an floating point value"}
        return Response(json.dumps(error), status=400, mimetype='application/json')
    product.update(
        {
            "name": content["name"],
            "description": content["description"],
            "type": content["type"].lower(),
            "manufacturer": content["manufacturer"],
            "last_update": datetime.datetime.utcnow(),
            "availability": content["availability"],
            "recent_min_cost": content["recent_min_cost"],
            "recent_avg_cost": content["recent_avg_cost"],
            "recent_max_cost": content["recent_max_cost"],
            "shopper": product["shopper"],
            "user": user_id
        }
    )
    client.put(product)
    product["self"] = url_root + 'products/' + str(product.key.id)
    product["id"] = product.key.id
    res = make_response(jsonify(product))
    res.headers["Content-Type"] = "application/json"
    res.headers['Location'] = url_root + 'products/' + str(product.key.id)
    res.status_code = 200
    return res

@app.route('/products/<id>', methods = ['PATCH'])
def product_patch(id):
    url_root = request.url_root
    payload = verify_jwt(request)
    # Content-Type Checks
    if request.content_type != 'application/json':
        error = {"Error": "Unsupported Media Type"}
        return Response(json.dumps(error), status=415, mimetype='application/json')
    # Accept Check
    if 'application/json' not in request.accept_mimetypes:
        error = {"Error": "Not Acceptable"}
        return Response(json.dumps(error), status=406, mimetype='application/json')
    product_key = client.key(constants.products, int(id))
    product = client.get(key=product_key)
    user_id = payload["sub"]
    if "user" not in product or user_id != product["user"]:
        error = {"Error": "Not authorized to access this shopper"}
        return Response(json.dumps(error), status=403, mimetype='application/json')
    if not product:
        error = {"Error": "No product with this product_id exists"}
        return Response(json.dumps(error), status=404, mimetype='application/json')
    content = request.get_json()
    if 'id' in content:
        error = {"Error": "The id cannot be modified"}
        return Response(json.dumps(error), status=400, mimetype='application/json')
    if 'name' in content:
        product['name'] = content['name']
    if 'description' in content:
        product['description'] = content['description']
    if 'manufacturer' in content:
        product['manufacturer'] = content['manufacturer']
    if 'type' in content:
        product['type'] = content['type'].lower()
    if 'availability' in content:
        product['availability'] = content['availability']
    if 'recent_min_cost' in content:
        if not is_float(content['recent_min_cost']):
            error = {"Error": "The recent_min_cost MUST be a Floating Point value"}
            return(Response(json.dumps(error), status=400, mimetype='application/json'))
        product['recent_min_cost'] = content['recent_min_cost']
    if 'recent_avg_cost' in content:
        if not is_float(content['recent_avg_cost']):
            error = {"Error": "The recent_avg_cost MUST be a Floating Point value"}
            return(Response(json.dumps(error), status=400, mimetype='application/json'))
        product['recent_avg_cost'] = content['recent_avg_cost']
    if 'recent_max_cost' in content:
        if not is_float(content['recent_max_cost']):
            error = {"Error": "The recent_max_cost MUST be a Floating Point value"}
            return(Response(json.dumps(error), status=400, mimetype='application/json'))
        product['recent_max_cost'] = content['recent_max_cost']
    product['last_update'] = datetime.datetime.utcnow()
    client.put(product)
    product['id'] = product.key.id
    product['self'] = url_root + 'products/' + str(product.key.id)
    res = make_response(jsonify(product))
    res.headers["Content-Type"] = "application/json"
    res.headers['Location'] = url_root + 'products/' + str(product.key.id)
    res.status_code = 200
    return res

@app.route('/products/<id>', methods = ['DELETE'])
def product_delete(id):
    payload = verify_jwt(request)
    product_key = client.key(constants.products, int(id))
    product = client.get(key=product_key)
    user_id = payload["sub"]
    if "user" not in product or user_id != product["user"]:
        error = {"Error": "Not authorized to access this shopper"}
        return Response(json.dumps(error), status=403, mimetype='application/json')
    if not product:
        error = {"Error": "No product with this product_id exists"}
        return Response(json.dumps(error), status=404, mimetype='application/json')
    client.delete(product_key)
    return "", 204

# Relationship Operations
# Shopper and Product Relationship Endpoints
@app.route('/shoppers/<shopper_id>/products/<product_id>', methods=['PUT', 'DELETE'])
def assign_remove_product_to_shopper(shopper_id, product_id):
    url_root = request.url_root
    payload = verify_jwt(request)
    user_id = payload["sub"]
    product_key = client.key(constants.products, int(product_id))
    product = client.get(key=product_key)
    shopper_key = client.key(constants.shoppers, int(shopper_id))
    shopper = client.get(key=shopper_key)
    if "user" not in product or "user" not in shopper or user_id != product["user"] \
            or user_id != shopper["user"]:
        error = {"Error": "Not authorized to access this shopper"}
        return Response(json.dumps(error), status=403, mimetype='application/json')
    if not shopper or not product:
        error = {"Error": "The specified shopper and/or product does not exist"}
        return Response(json.dumps(error), status=404, mimetype='application/json')
    if request.method == 'PUT':
        if product["shopper"] and product["shopper"]["id"] is not None:
            if int(product["shopper"]["id"]) != shopper.key.id:
                error = {"Error": "The product is already associated with another shopper"}
                return Response(json.dumps(error), status=403, mimetype='application/json')
            else:
                error = {"Error": "The product is already associated with this shopper"}
                return Response(json.dumps(error), status=403, mimetype='application/json')
        # Add - Product to Shopper Object
        product_existing_relative = False
        prod_list = []
        if shopper["products"]:
            for prod in shopper["products"]:
                if prod['id'] != product.key.id:
                    product_existing_relative = True
                prod_list.append(prod)
        if not product_existing_relative:
            prod_url = url_root + 'products/' + str(product.key.id)
            new_relative = {
                "id": product.key.id,
                "self": prod_url
            }
            prod_list.append(new_relative)
        shopper["products"] = prod_list
        # Add - Shopper to Product Object
        product["shopper"] = {
            "id": shopper.key.id,
            "self": url_root + 'shoppers/' + str(shopper.key.id)
        }
    elif request.method == 'DELETE':
        if shopper["products"] is None or len(shopper["products"]) == 0:
            error = {"Error": "This product is not currently associated with this shopper"}
            return Response(json.dumps(error), status=404, mimetype='application/json')
        print(shopper)
        print(product)
        if int(shopper_id) != product["shopper"]["id"]:
            error = {"Error": "This product is currently associated with another shopper"}
            return Response(json.dumps(error), status=404, mimetype='application/json')
        # Add - Product to Shopper Object
        prod_list = []
        for prod in shopper["products"]:
            if prod['id'] != product.key.id:
                prod_list.append(prod)
        shopper["products"] = prod_list
        # Add - Shopper to Product Object
        product["shopper"] = None
    client.put(product)
    client.put(shopper)
    return "", 204


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)