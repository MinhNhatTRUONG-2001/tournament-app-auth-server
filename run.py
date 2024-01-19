import os
from app import app

if __name__ == '__main__':
    app.run(debug = True, host=os.getenv("FLASK_HOST_URL"), port = 5000)