import re
import requests

def validate_email_syntax(email = ''):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

def validate_password(password=''):
    digit_pattern = r"[0-9]"
    lowercase_pattern = r"[a-z]"
    uppercase_pattern = r"[A-Z]"
    special_character_pattern = r"\W|_"
    if len(password) < 8 or len(password) > 64 \
    or re.search(digit_pattern, password) is None or re.search(lowercase_pattern, password) is None \
    or re.search(uppercase_pattern, password) is None or re.search(special_character_pattern, password) is None:
        return False
    else:
        return True

def validate_unique_username_and_email(conn, cur, username, email): #validate while signing up
    unique_check_fields = {"username": username, "email": email}
    for field in unique_check_fields:
        try:
            cur.execute(f"SELECT id FROM auth.users WHERE {field} = '{unique_check_fields[field]}'")
            result = cur.fetchone()
            conn.commit()
        except Exception:
            #print(traceback.format_exc())
            conn.rollback()
            raise Exception("Error in database")
        if result is not None:
            return False, field.capitalize() + " must be unique!"
    return True, ""

def validate_unique_username(conn, cur, id, username): #validate while changing user info
    try:
        cur.execute(f"SELECT id FROM auth.users WHERE username = '{username}'")
        result = cur.fetchone()
        conn.commit()
    except Exception:
        #print(traceback.format_exc())
        conn.rollback()
        raise Exception("Error in database")
    if result is not None and result[0] != int(id):
        return False, username.capitalize() + " must be unique!"
    return True, ""

def validate_country(country = ''):
    if country == '':
        return True
    headers = {
        "Content-Type": "application/json"
    }
    request_body = {
        "country": country
    }
    response = requests.post("https://countriesnow.space/api/v0.1/countries/codes", json=request_body, headers=headers)
    data = response.json()
    return not data["error"]

def validate_phone(phone):
    if not phone or phone.isdigit() and len(phone) <= 15 and phone[0] != '0':
        return True
    else:
        return False