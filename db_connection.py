import psycopg2
from dotenv import load_dotenv
import os

load_dotenv()
dbname = os.getenv('POSTGRESQL_DATABASE_NAME')
user = os.getenv('POSTGRESQL_USERNAME')
password = os.getenv('POSTGRESQL_PASSWORD')
host = os.getenv('POSTGRESQL_HOST')
port = os.getenv('POSTGRESQL_PORT')

conn = psycopg2.connect(dbname=dbname, user=user, password=password, host=host, port=port)
conn.autocommit = False
cur = conn.cursor()