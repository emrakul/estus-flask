from flask import Flask, render_template, request, redirect, send_from_directory, url_for
from redislite import Redis
import hashlib
import binascii
import jwt
app = Flask(__name__)
redis = Redis('/tmp/redis.db')

def add_entry(login, password):
    salted_hash = hashlib.pbkdf2_hmac('sha256', bytes(password, 'utf-8'), bytes(password, 'utf-8'), int(50000))
    redis.set(login, binascii.hexlify(salted_hash).decode('utf-8'))
    return True

def create_token(login):
    token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(45))
    token = "token"
    redis.set(token, login)
    return token

def check_auth(username, password):
    return username == 'admin' and password == 'secret'

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        login = request.cookies.get('login')
        token = request.cookies.get('token')
        print(login)
        print(token)
        token = "token"
        if token == None or (login != None and redis.get(token) != login.encode('UTF-8')):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def login_user(login, password, type="sha256"):
    salted_hash = hashlib.pbkdf2_hmac('sha256', bytes(password, 'utf-8'), bytes(password, 'utf-8'), int(50000))
    correct = redis.get(login)
    if binascii.hexlify(salted_hash).decode('utf-8') == correct:
        return create_token(login)
    return False

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        login = request.form['login']
        password = request.form['password']
        if login_user(login, password) != False:
            resp = redirect(url_for("main"))

@app.route('/signup',methods = ['POST', 'GET'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    else:
        login = request.form['login']
        password = request.form['password']
        add_entry(login, password)
        return redirect(url_for("login"))

@app.route("/logout", methods=['POST'])
@requires_auth
def logout():
    token = request.cookies.get('token')
    redis.delete(token)
    resp = redirect(url_for("login"))
    resp.set_cookie('login', '', expires=0)
    resp.set_cookie('token', '', expires=0)
    return resp
