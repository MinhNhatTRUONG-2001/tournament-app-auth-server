import re

def validate_email_syntax(email):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

def validate_unique_username_and_email(conn, cur, username, email):
    unique_check_fields = {"username": username, "email": email}
    for field in unique_check_fields:
        try:
            cur.execute(f"SELECT * FROM users.users WHERE {field} = '{unique_check_fields[field]}'")
            result = cur.fetchone()
            conn.commit()
        except Exception:
            #print(traceback.format_exc())
            conn.rollback()
            raise Exception("Error in database")
        if result is not None:
            return False, field.capitalize() + " must be unique!"
    return True, ""