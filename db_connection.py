from dotenv import load_dotenv
import os

load_dotenv()
dbname = os.getenv('POSTGRESQL_DATABASE_NAME')
dbuser = os.getenv('POSTGRESQL_USERNAME')
dbpassword = os.getenv('POSTGRESQL_PASSWORD')
dbhost = os.getenv('POSTGRESQL_HOST')
dbport = os.getenv('POSTGRESQL_PORT')