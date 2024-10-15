from flask import Blueprint, jsonify, request
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import requests
import jwt
from datetime import datetime, timedelta
from config import GOOGLE_CLIENT_ID, ALLOWED_EMAILS, SECRET_KEY

google_login_bp = Blueprint('google_login', __name__)

def create_jwt_token(user_info):
    payload = {
        "user_id": user_info['sub'],
        "email": user_info.get('email'),
        "name": user_info.get('name'),
        "exp": datetime.now() + timedelta(hours=1)  # Set expired time is 1 hour
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

@google_login_bp.route('/', methods=['POST'])
def login():
    token = request.json.get("token")
    if token is None:
        return jsonify({"error": "Token is missing"}), 400
    
    try:
        # Use GOOGLE_CLIENT_ID 
        id_info = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)

        if id_info['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')

        user_id = id_info['sub']
        user_email = id_info.get('email')
        user_name = id_info.get('name')
        user_picture = id_info.get('picture')

        if user_email not in ALLOWED_EMAILS:
            return jsonify({"error": "You are not authorized to access this application."}), 403
        
        jwt_token = create_jwt_token(id_info)

        return jsonify({
            "user_id": user_id,
            "email": user_email,
            "name": user_name,
            "picture": user_picture,
            "token": jwt_token
        })

    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@google_login_bp.route('/protected', methods=['GET'])
def protected():
    return jsonify({"message": "This is a protected route!"})