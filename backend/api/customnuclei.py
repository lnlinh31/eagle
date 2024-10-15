from flask import Blueprint, jsonify, request
from bson.json_util import dumps
from bson import ObjectId
from datetime import datetime
from config import db
from app import token_required
import os
from threading import Thread
import subprocess,re,json
import concurrent.futures
import xml.etree.ElementTree as ET
import hashlib
import logging
import os


customnuclei_bp = Blueprint('customnuclei', __name__)
targets_collection = db['targets']
jobs_collection = db['jobs']
vulnerabilities_collection = db['vulnerabilities']

@customnuclei_bp.route('/templates', methods=['GET'])
@token_required
def get_custom_template():
    template_folder = '/root/nuclei-templates/custom'
    
    # List all files in the template folder
    files = [f for f in os.listdir(template_folder) if os.path.isfile(os.path.join(template_folder, f))]
    
    templates = []
    
    for file_name in files:
        file_path = os.path.join(template_folder, file_name)
        try:
            with open(file_path, 'r') as file:
                content = file.read()
                templates.append({
                    'name': file_name,
                    'content': content
                })
        except Exception as e:
            # Handle potential read errors
            return jsonify({'error': str(e)}), 500
    
    return jsonify(templates)

# remove ANSI function
def remove_ansi_escape_sequences(line):
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)
# md5 hash function
def get_md5_hash(input_string: str) -> str:
    md5_hash = hashlib.md5()
    md5_hash.update(input_string.encode('utf-8'))
    md5_digest = md5_hash.hexdigest()
    
    return md5_digest

# Config for logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler('/var/log/gunicorn/error.log')
file_handler.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

def run_custom_nuclei_scan(target_domain, custom_template_name, job_id):
    target_url = target_domain 
    template_path = '/root/nuclei-templates/custom/' + custom_template_name
    command = ['nuclei', '-t', template_path, '-u', target_url, '-j']
    
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        total_findings = 0

        for line in iter(process.stdout.readline, b''):
            if line:
                try:
                    clean_line = remove_ansi_escape_sequences(line.decode('utf-8')).strip()
                    result = json.loads(clean_line)

                    # Extract data from result scan
                    severity = result.get('info', {}).get('severity', '').lower()
                    template_id = result.get('template-id', '')
                    tags = result.get('info', {}).get('tags', '')
                    extracted_results = result.get('extracted-results', [])
                    affected_item = result.get('matched-at', '')

                    if severity in ["critical", "high", "medium", "low"]:
                        hash_value = get_md5_hash(template_id + affected_item)
                        existing_vulnerability = vulnerabilities_collection.find_one({"hash": hash_value})
    
                        if not existing_vulnerability:
                            vulnerabilities_collection.insert_one({
                                "id": template_id,
                                "severity": severity,
                                "affectedItem": affected_item,
                                "createdAt": datetime.now(),
                                "domain": target_domain,
                                "hash": get_md5_hash(template_id + affected_item)
                            })
                            total_findings += 1
                            targets_collection.update_one({"domain": target_domain}, {"$inc": {"totalFinding": 1}})
                        else:
                            continue

                    elif severity == "info":
                        if template_id == "tech-detect":
                            tech_tag = result.get('matcher-name', '')
                            targets_collection.update_one({"domain": target_domain}, {"$addToSet": {"tag": tech_tag}})
                            logger.debug("Detected tech-detect template")
                        if 'tech' in tags and len(extracted_results) > 0:
                            if "wordpress" in template_id:
                                tech_tag = template_id + str(extracted_results)
                                targets_collection.update_one({"domain": target_domain}, {"$addToSet": {"tag": tech_tag}})
                                logger.debug("Added WordPress tech tag")
                            else:
                                for result in extracted_results:
                                    tech_tag = result
                                    targets_collection.update_one({"domain": target_domain}, {"$addToSet": {"tag": tech_tag}})
                                    logger.debug("Added extracted result tech tag")
                except json.JSONDecodeError as json_err:
                    logger.exception(f"Failed to decode JSON: {clean_line}")
                    jobs_collection.update_one(
                        {"_id": ObjectId(job_id)},
                        {"$set": {"status": "failed"}}
                    )
                    continue
        
        process.stdout.close()
        process.stderr.close()
        process.wait()

        # Update job status to 'done' and set total findings
        jobs_collection.update_one({"_id": ObjectId(job_id)}, {"$set": {"status": "done", "totalFinding": total_findings}})

    except Exception as e:
        logger.exception(f"An error occurred while running nuclei scan for {target_domain}: {e}")
        jobs_collection.update_one(
            {"_id": ObjectId(job_id)},
            {"$set": {"status": "failed"}}
        )


@customnuclei_bp.route('/custom-scan', methods=['POST'])
@token_required
def create_custom_scan():
    data = request.get_json()

    # Extracting data from the request body
    template = data.get('template', {})
    target_tag = data.get('targetTag')
    # schedule = data.get('schedule')

    # Validate the required fields
    if not template or not target_tag:
        return jsonify({'error': 'Template and targetTag are required'}), 400

    # name of template
    template_name = template.get('name')

    if not template_name:
        return jsonify({'error': 'Template name is required'}), 400

    # Collect all targets have tag match with target_tag
    targets = list(targets_collection.find({"tag": target_tag}))

    def execute_scans():
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for target in targets:
                # check if the target is already
                if target:
                    # Create job for target
                    job = {
                        "typeJob": "custom-nuclei",
                        "status": "running",
                        "target": target['domain'] + ':' + template_name,  # Thay đổi template thành template_name
                        "tag": [target_tag],
                        "createdAt": datetime.now(),
                        "totalFinding": 0
                    }
                    # add job into jobs_collection and  get job_id
                    job_id = jobs_collection.insert_one(job).inserted_id
                    # run scan and  submit job into executor
                    futures.append(executor.submit(run_custom_nuclei_scan, target['domain'], template_name, str(job_id)))

    # add thread to run scans
    scan_thread = Thread(target=execute_scans)
    scan_thread.start()

    # Return the job ID for reference
    return jsonify({'message': 'Custom scan job created successfully'}), 201



