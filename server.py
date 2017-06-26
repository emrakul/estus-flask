from flask import Flask, render_template, request, redirect, send_from_directory, url_for
from redislite import Redis
from functools import wraps
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
        if redis.get(token) != login.encode('UTF-8'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def login_user(login, password):
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
            resp.set_cookie('login', login)
            resp.set_cookie('token', token)
            return resp

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

@app.route("/download1", methods=['GET'])
def send_file():
    return send_from_directory('/app', "file1")

@app.route("/download2", methods=['GET'])
def send_big_file():
    return send_from_directory('/app', "file2")

@app.route("/main", methods=['GET'])
@requires_auth
def main():
    return render_template('main.html')

@app.route('/calc', methods=['POST'])
@requires_auth
def primes():
    n = int(request.form['number'])
    primfac = []
    d = 2
    while d*d <= n:
        while (n % d) == 0:
            primfac.append(d)
            n //= d
        d += 1
    if n > 1:
       primfac.append(n)
    return str(primfac)

if __name__ == "__main__":
    app.run(host='0.0.0.0',  port=80)
