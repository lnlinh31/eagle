from flask import Blueprint, jsonify, request
from bson.json_util import dumps
from bson import ObjectId
from datetime import datetime
from config import db
from app import token_required

vulnerabilities_bp = Blueprint('vulnerabilities', __name__)
vulnerabilities_collection = db['vulnerabilities']

targets_collection = db['targets']

@vulnerabilities_bp.route('/', methods=['GET'])
@token_required
def get_vulnerabilities():
    vulnerabilities = vulnerabilities_collection.find().sort('createdAt', -1).limit(10000)
    
    # Create a list contain object vulnerabilities
    result = []
    
    for vulnerability in vulnerabilities:
        domain = vulnerability.get('domain')
        
        # Find target in collection targets base on domain
        target = targets_collection.find_one({'domain': domain})
        
        # If found target and tag, add tag from target
        if target and 'tag' in target:
            vulnerability['tag'] = target['tag']
            vulnerabilities_collection.update_one(
                {'_id': vulnerability['_id']}, 
                {'$set': {'tag': target['tag']}}
            )

        else:
            vulnerability['tag'] = []  # In case of not found tag
        
        result.append(vulnerability)
    
    return dumps(result), 200

@vulnerabilities_bp.route('/search', methods=['GET'])
@token_required
def search_vulnerabilities():
    keyword = request.args.get('keyword')
    query = {"$or": [{"id": {"$regex": keyword}}, {"domain": {"$regex": keyword}},{"tag": {"$regex": keyword}}, {"severity": {"$regex": keyword}}]}
    vulnerabilities = vulnerabilities_collection.find(query)
    return dumps(vulnerabilities)

@vulnerabilities_bp.route('/', methods=['POST'])
@token_required
def add_vulnerability():
    data = request.json
    vulnerability = {
        "id": data.get("id"),
        "severity": data.get("severity"),
        "affectedItem": data.get("affectedItem"),
        "createdAt": datetime.now(),
        "domain": data.get("domain")
    }
    vulnerabilities_collection.insert_one(vulnerability)
    return jsonify({"message": "Vulnerability added successfully"}), 201

@vulnerabilities_bp.route('/delete', methods=['POST'])
@token_required
def delete_targets():
    data = request.json
    vul_ids = data.get('vulnerabilities', [])
    for vul_id in vul_ids:
        vulnerabilities_collection.delete_one({"_id": ObjectId(vul_id)})
    return jsonify({"message": "vulnerabilities deleted successfully"}), 200