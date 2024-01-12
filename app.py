import datetime
import os
from db_connection import conn, cur
from flask import Flask, request
from flask_cors import CORS
from argon2 import PasswordHasher, exceptions
import jwt
import traceback

app = Flask(__name__)
CORS(app)

@app.route("/")
def it_works():
    return "<h1>Tournament Management Authentication Server works!</h1>"

@app.route("/sign_up", methods = ['POST'])
def sign_up():
    request_body = request.get_json()
    try:
        username = request_body["username"].strip()
        email = request_body["email"].strip()
        password = request_body["password"].strip()
        if username and email and password:
            unique_check_fields = {"username": username, "email": email}
            for field in unique_check_fields:
                cur.execute(f"SELECT * FROM users.users WHERE {field} = '{unique_check_fields[field]}'")
                result = cur.fetchone()
                conn.commit()
                if result is not None:
                    return {"isSuccess": False, "message": field.capitalize() + " must be unique!"}, 400
            ph = PasswordHasher()
            hashed_pwd = ph.hash(request_body["password"])
            try:
                cur.execute(f"""INSERT INTO users.users(username, email, password)
                    VALUES ('{username}', '{email}', '{hashed_pwd}')""")
                conn.commit()
                return {"isSuccess": True, "message": "Account created successfully!"}, 201
            except Exception:
                #print(traceback.format_exc())
                conn.rollback()
                raise Exception("Error in database")
        else:
            raise Exception
    except Exception:
        #print(traceback.format_exc())
        return {"isSuccess": False, "message": "Bad Request"}, 400
    
@app.route("/sign_in", methods = ['POST'])
def sign_in():
    request_body = request.get_json()
    try:
        username_or_email = request_body["username_or_email"].strip()
        password = request_body["password"].strip()
        if username_or_email and password:
            cur.execute(f"""SELECT id, email, password FROM users.users
                WHERE username = '{username_or_email}' OR email = '{username_or_email}'""")
            result = cur.fetchone()
            if result is None:
                raise ValueError
            try:
                ph = PasswordHasher()
                ph.verify(result[2], password)
                payload = {
                    "id": result[0],
                    "email": result[1],
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=60) #expired after 12 hours
                }
                token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm="HS512")
                return {"isSuccess": True, "message": "Signed in successfully!", "token": token}, 200
            except exceptions.VerifyMismatchError:
                raise ValueError
        else:
            raise Exception
    except ValueError:
        #print(traceback.format_exc())
        return {"isSuccess": False, "message": "Username or email or password is not correct"}, 400
    except Exception:
        #print(traceback.format_exc())
        return {"isSuccess": False, "message": "Bad Request"}, 400

@app.route("/get_username_by_token")
def get_username_by_token():
    try:
        headers = request.headers
        token = headers["Authorization"].split("Bearer ", 1)[1]
        decoded_object = jwt.decode(token, os.getenv("JWT_SECRET_KEY"), algorithms=["HS512"])
        cur.execute(f"SELECT username FROM users.users WHERE id = {decoded_object['id']}")
        username, = cur.fetchone()
        return {"isSuccess": True, "username": username}
    except jwt.exceptions.ExpiredSignatureError:
        #print(traceback.format_exc())
        return {"isSuccess": False, "message": "JWT signature expired!"}, 400
    except Exception:
        #print(traceback.format_exc())
        return {"isSuccess": False, "message": "Bad Request"}, 400

if __name__ == '__main__':
    app.run(debug = True, host=os.getenv("FLASK_HOST_URL"), port = 5000)