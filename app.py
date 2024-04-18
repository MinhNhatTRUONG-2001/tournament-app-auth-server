from datetime import datetime, timezone, timedelta
import os
import psycopg2
import pytz
from db_connection import dbname, dbuser, dbpassword, dbhost, dbport
from flask import Flask, render_template, request, url_for
from flask_cors import CORS
from argon2 import PasswordHasher, exceptions
import jwt
from flask_mail import Mail
from helpers.validations import *
import traceback

app = Flask(__name__)
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)
CORS(app)

from helpers.send_email import send_email

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
            #Check for valid email syntax and password
            if validate_email_syntax(email) and validate_password(password):
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
                cur.execute(f"""INSERT INTO auth.users(username, email, password, last_sign_in_time, last_username_change_time)
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
                cur.execute(f"""SELECT id, email, password FROM auth.users
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
                    cur.execute(f"""UPDATE auth.users
                                SET last_sign_in_time = '{datetime.now(timezone.utc)}'
                                WHERE id = {result[0]}""")
                    conn.commit()
                except Exception:
                    #print(traceback.format_exc())
                    conn.rollback()
                    raise Exception("Error in database")
                conn.close()
                return {"isSuccess": True, "message": "Signed in successfully", "token": token}
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
            cur.execute(f"SELECT username, email, last_username_change_time, country, phone FROM auth.users WHERE id = {decoded_object['id']}")
            result = cur.fetchone()
            conn.commit()
        except Exception:
            #print(traceback.format_exc())
            conn.rollback()
            raise Exception("Error in database")
        time_after_last_sign_in_time = datetime.now(timezone.utc) - result[2]
        next_username_change_time = (result[2] + timedelta(days=30, seconds=60)).astimezone(pytz.utc)
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
            "can_change_username": can_change_username,
            "next_username_change_time": next_username_change_time,
            "country": result[3],
            "phone": result[4]
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
        #Check if fields are null or empty, and validate country name and phone number
        new_username = request_body["username"].strip()
        country = request_body["country"].strip()
        phone = request_body["phone"].strip()
        if new_username and validate_country(country) and validate_phone(phone):
            #Finally check if new username is unique
            isUnique, message = validate_unique_username(conn, cur, decoded_object['id'], new_username)
            if not isUnique:
                conn.close()
                return {"isSuccess": False, "message": message}, 400
            try:
                cur.execute(f"SELECT last_username_change_time FROM auth.users WHERE id = {decoded_object['id']}")
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
                    cur.execute(f"""UPDATE auth.users
                                SET username = '{new_username}', last_username_change_time = '{datetime.now(timezone.utc)}'
                                WHERE id = {decoded_object['id']}""")
                    conn.commit()
                except Exception:
                    #print(traceback.format_exc())
                    conn.rollback()
                    raise Exception("Error in database")
            else:
                print("Username cannot be changed within 30 days since last change. Other user information updated successfully")
            #Change other information
            try:
                cur.execute(f"""UPDATE auth.users
                            SET country = '{country}', phone = '{phone}'
                            WHERE id = {decoded_object['id']}""")
                conn.commit()
            except Exception:
                #print(traceback.format_exc())
                conn.rollback()
                raise Exception("Error in database")
            conn.close()
            return {"isSuccess": True, "message": "User information updated successfully"}
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
        #Check if fields are null or empty and new password is valid
        current_password = request_body["current_password"].strip()
        new_password = request_body["new_password"].strip()
        if current_password and new_password and validate_password(new_password):
            #Check if user current password exists
            try:
                cur.execute(f"SELECT password FROM auth.users WHERE id = {decoded_object['id']}")
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
                    cur.execute(f"""UPDATE auth.users
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

@app.route("/forgot_password", methods = ["POST"])
def forgot_password():
    conn = psycopg2.connect(dbname=dbname, user=dbuser, password=dbpassword, host=dbhost, port=dbport)
    cur = conn.cursor()

    request_body = request.get_json()
    try:
        email = request_body["email"].strip()
        if email:
            #Check exist email in the database
            try:
                cur.execute(f"SELECT id FROM auth.users WHERE email = '{email}'")
                result = cur.fetchone()
                if result is not None:
                    id = result[0]
                else:
                    id = None
                conn.commit()
            except Exception:
                #print(traceback.format_exc())
                conn.rollback()
                raise Exception("Error in database")
            #Generate reset token
            payload = {
                "id": id,
                "email": email,
                "exp": datetime.now(timezone.utc) + timedelta(minutes=5)
            }
            token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm="HS512")
            #Prepare send_email parameters and send email
            reset_url = url_for('reset_password', token=token, _external=True)
            text_body = render_template("reset_email.txt", reset_url=reset_url)
            html_body = render_template("reset_email.html", reset_url=reset_url)
            email_subject = "Tournament Management Mobile Application - Password Reset"
            send_email(email_subject, os.getenv("MAIL_USERNAME"), [email], text_body, html_body)
            return {"isSuccess": True, "message": "A password reset request has been sent to your email"}
        else:
            raise Exception
    except Exception:
        #print(traceback.format_exc())
        conn.close()
        return {"isSuccess": False, "message": "Bad Request"}, 400

@app.route("/reset_password/<token>", methods = ["GET", "POST"])
def reset_password(token):
    if request.method == "GET":
        return render_template("reset_password.html")
    elif request.method == "POST":
        try:
            conn = psycopg2.connect(dbname=dbname, user=dbuser, password=dbpassword, host=dbhost, port=dbport)
            cur = conn.cursor()

            decoded_object = jwt.decode(token, os.getenv("JWT_SECRET_KEY"), algorithms=["HS512"])
            try:
                cur.execute(f"SELECT id, email FROM auth.users WHERE id = {decoded_object['id']} AND email = '{decoded_object['email']}'")
                result = cur.fetchone()
                if result is not None:
                    id, email = result[0], result[1]
                else:
                    id = email = None
                conn.commit()
            except Exception:
                #print(traceback.format_exc())
                conn.rollback()
                raise Exception("Error in database")
            if id is not None and email is not None:
                new_password = request.form.get("new_password")
                ph = PasswordHasher()
                new_hashed_password = ph.hash(new_password)
                try:
                    cur.execute(f"""UPDATE auth.users
                                SET password = '{new_hashed_password}'
                                WHERE id = {id}""")
                    conn.commit()
                except Exception:
                    #print(traceback.format_exc())
                    conn.rollback()
                    raise Exception("Error in database")
                conn.close()
                return render_template("reset_password_success.html")
            else:
                raise Exception
        except jwt.exceptions.ExpiredSignatureError:
            #print(traceback.format_exc())
            conn.close()
            return {"isSuccess": False, "message": "JWT signature expired"}, 400
        except Exception:
            conn.close()
            return {"isSuccess": False, "message": "Bad Request"}, 400

@app.route("/delete_user_account", methods = ["POST"])
def delete_user_account():
    conn = psycopg2.connect(dbname=dbname, user=dbuser, password=dbpassword, host=dbhost, port=dbport)
    cur = conn.cursor()

    headers = request.headers
    request_body = request.get_json()
    try:
        #Decode the token to get user id
        token = headers["Authorization"].split("Bearer ", 1)[1]
        decoded_object = jwt.decode(token, os.getenv("JWT_SECRET_KEY"), algorithms=["HS512"])
        #Verify user password
        try:
            cur.execute(f"""SELECT password FROM auth.users
                WHERE id = {decoded_object['id']}""")
            result = cur.fetchone()
            conn.commit()
        except Exception:
            #print(traceback.format_exc())
            conn.rollback()
            raise Exception("Error in database")
        try:
            ph = PasswordHasher()
            ph.verify(result[0], request_body["password"])
        except exceptions.VerifyMismatchError:
            conn.close()
            return {"isSuccess": False, "message": "Incorrect password"}, 400
        #Delete every tournament linked to the deleted user account
        try:
            cur.execute(f"SELECT id FROM data.tournaments WHERE user_id = {decoded_object['id']}")
            result = cur.fetchall()
            if result:
                for tid in result:
                    requests.delete(f"{os.getenv('TOURNAMENT_DATA_SERVER_URL')}/tournaments/{tid}", headers={'Authorization': headers["Authorization"]})
            conn.commit()
        except Exception:
            #print(traceback.format_exc())
            conn.rollback()
            raise Exception("Error in database")
        #Delete user account itself
        try:
            cur.execute(f"""DELETE FROM auth.users
                        WHERE id = {decoded_object['id']}""")
            conn.commit()
        except Exception:
            #print(traceback.format_exc())
            conn.rollback()
            raise Exception("Error in database")
        conn.close()
        return {"isSuccess": True, "message": "Account deleted successfully"}
    except jwt.exceptions.ExpiredSignatureError:
        #print(traceback.format_exc())
        conn.close()
        return {"isSuccess": False, "message": "JWT signature expired"}, 400
    except Exception:
        #print(traceback.format_exc())
        conn.close()
        return {"isSuccess": False, "message": "Bad Request"}, 400