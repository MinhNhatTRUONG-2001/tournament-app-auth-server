from datetime import datetime, timezone, timedelta
import os
import psycopg2
from db_connection import dbname, dbuser, dbpassword, dbhost, dbport
from flask import Flask, request
from flask_cors import CORS
from argon2 import PasswordHasher, exceptions
import jwt
from helpers.validations import validate_email_syntax, validate_unique_username_and_email
import traceback

app = Flask(__name__)
CORS(app)

@app.route("/")
def it_works():
    return "<h1>Tournament Management Authentication Server works!</h1>"

@app.route("/sign_up", methods = ["POST"])
def sign_up():
    conn = psycopg2.connect(dbname=dbname, user=dbuser, password=dbpassword, host=dbhost, port=dbport)
    cur = conn.cursor()

    request_body = request.get_json()
    try:
        #Check if fields are null or empty
        username = request_body["username"].strip()
        email = request_body["email"].strip()
        password = request_body["password"].strip()
        if username and email and password:
            #Check for valid email syntax
            if validate_email_syntax(email):
                #Finally, check for unique username and email in database
                isUnique, message = validate_unique_username_and_email(conn, cur, username, email)
                if not isUnique:
                    conn.close()
                    return {"isSuccess": False, "message": message}, 400
            else:
                raise Exception
            #Hash the password, set initial values of last_sign_in_time and last_username_change_time, and save the new user data
            ph = PasswordHasher()
            hashed_password = ph.hash(request_body["password"])
            last_sign_in_time = datetime.now(timezone.utc)
            last_username_change_time = datetime.now(timezone.utc)
            try:
                cur.execute(f"""INSERT INTO users.users(username, email, password, last_sign_in_time, last_username_change_time)
                    VALUES ('{username}', '{email}', '{hashed_password}', '{last_sign_in_time}', '{last_username_change_time}')
                    RETURNING id""")
                new_id = cur.fetchone()[0]
                conn.commit()
                payload = {
                    "id": new_id,
                    "email": email,
                    "exp": datetime.now(timezone.utc) + timedelta(hours=12)
                }
                token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm="HS512")
                conn.close()
                return {"isSuccess": True, "message": "Account created successfully", "token": token}, 201
            except Exception:
                #print(traceback.format_exc())
                conn.rollback()
                raise Exception("Error in database")
        else:
            raise Exception
    except Exception:
        #print(traceback.format_exc())
        conn.close()
        return {"isSuccess": False, "message": "Bad Request"}, 400
    
@app.route("/sign_in", methods = ["POST"])
def sign_in():
    conn = psycopg2.connect(dbname=dbname, user=dbuser, password=dbpassword, host=dbhost, port=dbport)
    cur = conn.cursor()

    request_body = request.get_json()
    try:
        #Check if fields are null or empty
        username_or_email = request_body["username_or_email"].strip()
        password = request_body["password"].strip()
        if username_or_email and password:
            #Check if username and password exist in the same row in the database
            try:
                cur.execute(f"""SELECT id, email, password FROM users.users
                    WHERE username = '{username_or_email}' OR email = '{username_or_email}'""")
                result = cur.fetchone()
                conn.commit()
            except Exception:
                #print(traceback.format_exc())
                conn.rollback()
                raise Exception("Error in database")
            if result is None:
                raise ValueError
            #Verify password, then return a token to user
            try:
                ph = PasswordHasher()
                ph.verify(result[2], password)
                payload = {
                    "id": result[0],
                    "email": result[1],
                    "exp": datetime.now(timezone.utc) + timedelta(hours=12)
                }
                token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm="HS512")
                try:
                    cur.execute(f"""UPDATE users.users
                                SET last_sign_in_time = '{datetime.now(timezone.utc)}'
                                WHERE id = {result[0]}""")
                    conn.commit()
                except Exception:
                    #print(traceback.format_exc())
                    conn.rollback()
                    raise Exception("Error in database")
                conn.close()
                return {"isSuccess": True, "message": "Signed in successfully", "token": token}, 200
            except exceptions.VerifyMismatchError:
                raise ValueError
        else:
            raise Exception
    except ValueError:
        #print(traceback.format_exc())
        conn.close()
        return {"isSuccess": False, "message": "Username or email or password is not correct"}, 400
    except Exception:
        #print(traceback.format_exc())
        conn.close()
        return {"isSuccess": False, "message": "Bad Request"}, 400

@app.route("/get_user_information")
def get_user_information():
    conn = psycopg2.connect(dbname=dbname, user=dbuser, password=dbpassword, host=dbhost, port=dbport)
    cur = conn.cursor()

    headers = request.headers
    try:
        #Decode the token to get user id, then retrieve user information by the id
        token = headers["Authorization"].split("Bearer ", 1)[1]
        decoded_object = jwt.decode(token, os.getenv("JWT_SECRET_KEY"), algorithms=["HS512"])
        try:
            cur.execute(f"SELECT username, email, last_username_change_time FROM users.users WHERE id = {decoded_object['id']}")
            result = cur.fetchone()
            conn.commit()
        except Exception:
            #print(traceback.format_exc())
            conn.rollback()
            raise Exception("Error in database")
        time_after_last_sign_in_time = datetime.now(timezone.utc) - result[2]
        if time_after_last_sign_in_time >= timedelta(days=30):
            can_change_username = True
        else:
            can_change_username = False
        conn.close()
        return {
            "isSuccess": True,
            "id": decoded_object['id'],
            "username": result[0],
            "email": result[1],
            "can_change_username": can_change_username
        }
    except jwt.exceptions.ExpiredSignatureError:
        #print(traceback.format_exc())
        conn.close()
        return {"isSuccess": False, "message": "JWT signature expired"}, 400
    except Exception:
        #print(traceback.format_exc())
        conn.close()
        return {"isSuccess": False, "message": "Bad Request"}, 400
    
@app.route("/change_user_information", methods = ["POST"])
def change_user_information():
    conn = psycopg2.connect(dbname=dbname, user=dbuser, password=dbpassword, host=dbhost, port=dbport)
    cur = conn.cursor()

    headers = request.headers
    request_body = request.get_json()
    try:
        #Decode the token to get user id
        token = headers["Authorization"].split("Bearer ", 1)[1]
        decoded_object = jwt.decode(token, os.getenv("JWT_SECRET_KEY"), algorithms=["HS512"])
        #Check if fields are null or empty
        new_username = request_body["username"].strip()
        if new_username:
            try:
                cur.execute(f"SELECT last_username_change_time FROM users.users WHERE id = {decoded_object['id']}")
                result = cur.fetchone()
                conn.commit()
            except Exception:
                #print(traceback.format_exc())
                conn.rollback()
                raise Exception("Error in database")
            time_after_last_sign_in_time = datetime.now(timezone.utc) - result[0]
            #If the last_username_change_time is larger than 30 days, the username can be changed
            if time_after_last_sign_in_time >= timedelta(days=30):
                try:
                    cur.execute(f"""UPDATE users.users
                                SET username = '{new_username}', last_username_change_time = '{datetime.now(timezone.utc)}'
                                WHERE id = {decoded_object['id']}""")
                    conn.commit()
                except Exception:
                    #print(traceback.format_exc())
                    conn.rollback()
                    raise Exception("Error in database")
                conn.close()
                return {"isSuccess": True, "message": "Password changed successfully"}
            else:
                raise Exception("time_after_last_sign_in_time is smaller than 30 days")
        else:
            raise Exception
    except jwt.exceptions.ExpiredSignatureError:
        #print(traceback.format_exc())
        conn.close()
        return {"isSuccess": False, "message": "JWT signature expired"}, 400
    except Exception:
        print(traceback.format_exc())
        conn.close()
        return {"isSuccess": False, "message": "Bad Request"}, 400
    
@app.route("/change_password", methods = ["POST"])
def change_password():
    conn = psycopg2.connect(dbname=dbname, user=dbuser, password=dbpassword, host=dbhost, port=dbport)
    cur = conn.cursor()

    headers = request.headers
    request_body = request.get_json()
    try:
        #Decode the token to get user id
        token = headers["Authorization"].split("Bearer ", 1)[1]
        decoded_object = jwt.decode(token, os.getenv("JWT_SECRET_KEY"), algorithms=["HS512"])
        #Check if fields are null or empty
        current_password = request_body["current_password"].strip()
        new_password = request_body["new_password"].strip()
        if current_password and new_password:
            #Check if user password exists
            try:
                cur.execute(f"SELECT password FROM users.users WHERE id = {decoded_object['id']}")
                result = cur.fetchone()
                if result:
                    hashed_password = result[0]
                else:
                    hashed_password = None
                conn.commit()
            except Exception:
                #print(traceback.format_exc())
                conn.rollback()
                raise Exception("Error in database")
            if not hashed_password:
                conn.close()
                return {"isSuccess": False, "message": "User is not found"}, 404
            #Verify current password and save new hashed password to the database
            try:
                ph = PasswordHasher()
                ph.verify(hashed_password, current_password)
                new_hashed_password = ph.hash(new_password)
                try:
                    cur.execute(f"""UPDATE users.users
                                SET password = '{new_hashed_password}'
                                WHERE id = {decoded_object['id']}""")
                    conn.commit()
                except Exception:
                    #print(traceback.format_exc())
                    conn.rollback()
                    raise Exception("Error in database")
                conn.close()
                return {"isSuccess": True, "message": "Password changed successfully"}
            except exceptions.VerifyMismatchError:
                conn.close()
                return {"isSuccess": False, "message": "Incorrect current password"}, 400
        else:
            raise Exception
    except jwt.exceptions.ExpiredSignatureError:
        #print(traceback.format_exc())
        conn.close()
        return {"isSuccess": False, "message": "JWT signature expired"}, 400
    except Exception:
        #print(traceback.format_exc())
        conn.close()
        return {"isSuccess": False, "message": "Bad Request"}, 400
        

if __name__ == '__main__':
    app.run(debug = True, host=os.getenv("FLASK_HOST_URL"), port = 5000)