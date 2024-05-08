# Tournament Management Mobile Application - Authentication Server
This server is responsible for user authentication and manage user information. The server communicates mainly with the `auth` schema in the PostgreSQL database.
## Environment variables
After cloning this project, please create a .env file and add the following variables:
- FLASK_HOST_URL: The hostname that listens on the server. Set 0.0.0.0 to allow any host.
- POSTGRESQL_DATABASE_NAME: For example, tournaments
- POSTGRESQL_USERNAME: For example, postgres
- POSTGRESQL_PASSWORD
- POSTGRESQL_HOST: For example, localhost
- POSTGRESQL_PORT: For example, 5432
- JWT_SECRET_KEY: The secret key string for encoding and decoding JWT tokens.
- MAIL_USERNAME: The email address of the Flask-Mail service, used for sending email messages. For example, test@example.com
- MAIL_PASSWORD: The password of the above email address.
- TOURNAMENT_DATA_SERVER_URL: URL of the tournament data server. For example, http://192.168.90.69:5244
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