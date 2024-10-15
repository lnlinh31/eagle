from pymongo import MongoClient
from google.oauth2 import id_token
from oauthlib.oauth2 import WebApplicationClient
import os

# Thiết lập kết nối với MongoDB
mongo_uri = os.getenv('MONGO_URI')
client = MongoClient(mongo_uri)
db = client['eagle_db']

# OAuth2 client setup
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = os.getenv('GOOGLE_DISCOVERY_URL')

ALLOWED_EMAILS =os.getenv('ALLOWED_EMAILS').split(',')

SECRET_KEY = os.getenv('SECRET_KEY')
SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL')
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')

SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')

DIGITAL_OCEAN_ACCESS_TOKEN = os.getenv('DIGITAL_OCEAN_ACCESS_TOKEN')
DIGITAL_OCEAN_API_URL_DROPLETS = os.getenv('DIGITAL_OCEAN_API_URL_DROPLETS')
DIGITAL_OCEAN_API_URL_LOAD_BALANCERS = os.getenv('DIGITAL_OCEAN_API_URL_LOAD_BALANCERS')
DIGITAL_OCEAN_API_URL_FLOATING_IPS = os.getenv('DIGITAL_OCEAN_API_URL_FLOATING_IPS')

CLOUDFLARE_ACCESS_TOKEN = os.getenv('CLOUDFLARE_ACCESS_TOKEN')


client = WebApplicationClient(GOOGLE_CLIENT_ID)

def get_google_provider_cfg():
    import requests
    return requests.get(GOOGLE_DISCOVERY_URL).json()