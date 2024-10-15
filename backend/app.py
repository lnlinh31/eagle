from flask import Flask, request, jsonify
from flask_cors import CORS
import os, jwt, requests
from pymongo import MongoClient
from functools import wraps
from config import SECRET_KEY
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import time
from SchedulerFunction import check_open_ports, crawl_public_ip, run_nmap, crawl_domain_from_all,check_dangling_record_dns,crawl_bugbounty_domain
import os, jwt, requests 

app = Flask(__name__)
CORS(app)  # Allows cross-origin requests to connect with React front end

# Set up the scheduler to run the check periodically
scheduler = BackgroundScheduler(daemon=True)
# scheduler.add_job(check_open_ports, CronTrigger(hour=1, minute=0, day_of_week='mon,wed,fri'))
# # scheduler.add_job(check_dangling_record_dns, CronTrigger(hour=10, minute=15, day_of_week='mon'))
# scheduler.add_job(crawl_public_ip, CronTrigger(hour=8, minute=0, day_of_week='mon,wed,fri'))
# scheduler.add_job(run_nmap, CronTrigger(hour=12, minute=0, day_of_week='1-5'))

# scheduler.add_job(crawl_domain_from_all, CronTrigger(hour=3, minute=15, day_of_week='1-2'))
scheduler.add_job(crawl_bugbounty_domain, CronTrigger(hour=9, minute=10, day_of_week='1-5'))
scheduler.start()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        try:
            token = token.split(" ")[1]  # Remove Bearer prefix
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 401
        except (jwt.InvalidTokenError, IndexError):
            return jsonify({"message": "Invalid token!"}), 401

        return f(*args, **kwargs)
    return decorated

# Register blueprint from api folder
from api import api_bp
app.register_blueprint(api_bp, url_prefix='/api')

if __name__ == '__main__':
    app.run(host='0.0.0.0')
    
