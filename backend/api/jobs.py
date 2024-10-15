from flask import Blueprint, jsonify, request
from bson.json_util import dumps
from bson import ObjectId
from datetime import datetime
from config import db
from app import token_required

jobs_bp = Blueprint('jobs', __name__)
jobs_collection = db['jobs']

@jobs_bp.route('/', methods=['GET'])
@token_required
def get_jobs():
    # Limit the number of jobs up to 10000
    jobs = jobs_collection.find().sort('createdAt', -1).limit(10000)
    return dumps(jobs), 200

@jobs_bp.route('/search', methods=['GET'])
@token_required
def search_jobs():
    keyword = request.args.get('keyword')
    query = {"$or": [{"typeJob": {"$regex": keyword}}, {"status": {"$regex": keyword}}, {"target": {"$regex": keyword}}]}
    jobs = jobs_collection.find(query)
    return dumps(jobs)

@jobs_bp.route('/delete', methods=['POST'])
@token_required
def delete_jobs():
    data = request.json
    job_ids = data.get('jobs', [])
    for job_id in job_ids:
        jobs_collection.delete_one({"_id": ObjectId(job_id)})
    return jsonify({"message": "Jobs deleted successfully"}), 200