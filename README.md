# Tournament Management Mobile Application - Authentication Server
This server is responsible for user authentication and manage user information. The server communicates mainly with the `auth` schema in the PostgreSQL database.
## Database schema
![Database schema](https://drive.google.com/thumbnail?id=13SmD8vU9qfhLpsRa0FEM-rZPTxkGYXts&sz=w1000)
## List of endpoints
- /sign_up (POST)
    - Body keys: email (string), username (string), password (string)
- /sign_in (POST)
    - Body keys: username_or_email (string), password (string)
    - /username/<user_id> (GET)
- /get_user_information (GET)
    - Header key: Authorization
- /change_user_information (POST)
    - Header key: Authorization
    - Body keys: new_username (string), country (string), phone (string)
- /change_password (POST)
    - Header key: Authorization
    - Body keys: current_password (string), new_password (string)
- /forgot_password (POST)
    - Body key: email (string)
- /reset_password/<token> (GET, POST)
- /delete_user_account (POST)
    - Header key: Authorization
    - Body key: password (string)