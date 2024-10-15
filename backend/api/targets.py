import hashlib
from flask import Blueprint, jsonify, request
from bson.json_util import dumps
from bson import ObjectId
from datetime import datetime
from config import db, SHODAN_API_KEY
from app import token_required
from threading import Thread
import subprocess,re,json
import concurrent.futures
import xml.etree.ElementTree as ET
import logging,requests
from requests.exceptions import RequestException, Timeout, SSLError
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from pymongo import UpdateOne
import pandas as pd
import threading

targets_bp = Blueprint('targets', __name__)
targets_collection = db['targets']
jobs_collection = db['jobs']
vulnerabilities_collection = db['vulnerabilities']

shodan_api_key = SHODAN_API_KEY
shodan_base_url = "https://api.shodan.io"

# setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler('/var/log/gunicorn/error.log')
file_handler.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# API -----------------------------------------------------------------------------

@targets_bp.route('/', methods=['GET'])
@token_required
def get_targets():
    targets = targets_collection.find().sort('lastUpdate', -1).limit(10000)
    return dumps(targets)

@targets_bp.route('/tags', methods=['GET'])
@token_required
def get_unique_tags():
    # Find all targets and extract their 'tag' arrays
    targets = targets_collection.find({}, {"tag": 1})  # Only retrieve the 'tag' field
    tags_set = set()

    for target in targets:
        tags = target.get('tag', [])
        tags_set.update(tags)  # Add tags to the set to ensure uniqueness

    return jsonify(list(tags_set))

@targets_bp.route('/search', methods=['GET'])
@token_required
def search_targets():
    keyword = request.args.get('keyword')
    query = {"$or": [{"domain": {"$regex": keyword}}, {"tag": {"$regex": keyword}},{"rootDomain": {"$regex": keyword}},{"ports": {"$regex": keyword}}, {"dns_content": {"$regex": keyword}}, {"type": {"$regex": keyword}}, {"ip": {"$regex": keyword}}]}
    targets = targets_collection.find(query)
    return dumps(targets)

@targets_bp.route('/', methods=['POST'])
@token_required
def add_target():
    data = request.json
    domain = data.get('domain')
    
    if targets_collection.find_one({"domain": domain}):
        return jsonify({"message": "Duplicate domain"}), 409

    new_target = {
        "domain": domain,
        "rootDomain": data.get('rootDomain'),
        "ports": [],
        "tag": [],
        "createdAt": datetime.now(),
        "lastUpdate": datetime.now(),
        "in_public_ips": "n/a",
        "ip": "n/a",
        "record_id": "n/a",
        "type": "n/a",
        "dns_content": "n/a",
        "zone_id": "n/a",
        "totalVulnerability": 0,
        "totalSubDomains": 0
    }
    targets_collection.insert_one(new_target)
    return jsonify({"message": "Target added successfully"}), 201

@targets_bp.route('/import', methods=['POST'])
@token_required
def import_targets_csv():
    csv_file = request.files.get('csv')

    if not csv_file or not csv_file.filename.endswith('.csv'):
        return jsonify({"message": "Invalid file format"}), 400

    try:
        df = pd.read_csv(csv_file)
        
        operations = []
        batch_size = 100  

        for index, row in df.iterrows():
            domain = row['domain']
            tag = str(row['tag']).split('|')
            new_target = {
                "domain": domain,
                "rootDomain": row['rootDomain'],
                "ports": [],
                "tag": tag,
                "createdAt": datetime.now(),
                "lastUpdate": datetime.now(),
                "in_public_ips": "n/a",
                "ip": "n/a",
                "record_id": "n/a",
                "type": "n/a",
                "zone_id": "n/a",
                "dns_content": "n/a",
                "totalVulnerability": 0,
                "totalSubDomains": 0
            }

            
            operations.append(UpdateOne({"domain": domain}, {"$setOnInsert": new_target}, upsert=True))

            # Perform bulk_write 
            if len(operations) >= batch_size:
                targets_collection.bulk_write(operations)
                operations = []  # Reset list of operations after bulk_write

        # RUn bulk_write for rest of operations
        if operations:
            targets_collection.bulk_write(operations)

        return jsonify({"message": "Targets imported successfully"}), 200

    except Exception as e:
        logging.error(f"Error importing targets: {str(e)}")  
        return jsonify({"message": "Failed to import target as {}".format(str(e))}), 500

@targets_bp.route('/delete', methods=['POST'])
@token_required
def delete_targets():
    data = request.json
    target_ids = data.get('targets', [])
    for target_id in target_ids:
        targets_collection.delete_one({"_id": ObjectId(target_id)})
    return jsonify({"message": "Targets deleted successfully"}), 200

@targets_bp.route('/update', methods=['POST'])
@token_required
def update_targets():
    try:
        # Lấy danh sách targets đã chỉnh sửa từ body của request
        updated_targets = request.json

        # Kiểm tra nếu không có target nào được gửi lên
        if not updated_targets:
            return jsonify({"error": "No targets provided for update"}), 400

        # Duyệt qua từng target để cập nhật trong MongoDB
        for target in updated_targets:
            target_id = target.get('_id')
            if not target_id:
                return jsonify({"error": "Target ID is missing"}), 400

            # Xóa ID khỏi target để tránh lỗi khi cập nhật
            del target['_id']

            # Cập nhật target dựa trên target_id
            targets_collection.update_one(
                {'_id': ObjectId(target_id)},
                {'$set': target}
            )

        # Trả về kết quả thành công
        return jsonify({"message": "Targets updated successfully"}), 200

    except Exception as e:
        # Xử lý lỗi nếu có vấn đề xảy ra
        print(f"Error updating targets: {e}")
        return jsonify({"error": f"Error updating targets: {e}"}), 500

def create_shodan_job(shodan_query):
    try:
        # Add new job in jobs collection
        job = {
            "typeJob": "shodan",
            "target": shodan_query,
            "status": "running",
            "tag": [],
            "createdAt": datetime.now(),
            "totalFinding": 0
        }
        job_id = jobs_collection.insert_one(job).inserted_id
        
        # response with job_id
        response = jsonify({
            "message": "Shodan query initiated",
            "job_id": str(job_id)
        })
        response.status_code = 202
        
        return response, job_id
    except Exception as e:
        logger.exception(f"Error creating Shodan job: {str(e)}")
        return jsonify({"error": str(e)}), 500

def execute_shodan_query(job_id, shodan_query):
    try:
        logger.debug(f"Starting Shodan query for job {job_id}")
        
        # API call function
        def fetch_page(page_num):
            try:
                api_url = f"https://api.shodan.io/shodan/host/search?key={shodan_api_key}&query={shodan_query}&page={page_num}"
                response = requests.get(api_url, timeout=60)
                
                # Check if response is valid
                if response.status_code != 200:
                    logger.error(f"Shodan query failed on page {page_num} for job {job_id}: {response.text}")
                    return None

                response_data = response.json()
                return response_data.get('matches', [])
            except Exception as e:
                logger.exception(f"Error fetching page {page_num}: {str(e)}")
                return None
        
        # Fetch the first page to get the total number of results and pages
        api_url = f"https://api.shodan.io/shodan/host/search?key={shodan_api_key}&query={shodan_query}"
        initial_response = requests.get(api_url, timeout=60)
        initial_data = initial_response.json()

        if initial_response.status_code != 200:
            logger.error(f"Shodan query failed for job {job_id}: {initial_data}")
            jobs_collection.update_one({"_id": ObjectId(job_id)}, {"$set": {"status": "failed"}})
            return

        total_results = initial_data.get('total', 0)
        results_per_page = len(initial_data.get('matches', []))
        total_pages = (total_results // results_per_page) + 1 if results_per_page > 0 else 1
        
        logger.debug(f"Total results: {total_results}, Pages: {total_pages}")
        
        # Process the first page immediately
        results = initial_data.get('matches', [])
        for result in results:
            process_result(result,shodan_query)
        
        # Use ThreadPoolExecutor for parallel fetching of other pages
        with ThreadPoolExecutor(max_workers=1) as executor:
            futures = [executor.submit(fetch_page, page_num) for page_num in range(2, total_pages + 1)]
            
            for future in as_completed(futures):
                page_results = future.result()
                if page_results:
                    for result in page_results:
                        process_result(result,shodan_query)
        
        # Mark the job as done
        jobs_collection.update_one({"_id": ObjectId(job_id)}, {"$set": {"status": "done"}})
        logger.debug(f"Shodan query completed for job {job_id}")
    
    except Exception as e:
        logger.exception(f"Error during Shodan query for job {job_id}: {str(e)}")
        jobs_collection.update_one({"_id": ObjectId(job_id)}, {"$set": {"status": "failed"}})

def process_result(result, shodan_query):
    """
    Processes each individual result from Shodan's API
    """
    try:
        host = result.get('ip_str')
        ports = result.get('port', [])
        host_url = f"https://api.shodan.io/shodan/host/{host}?key={shodan_api_key}"
        
        # Fetch additional host information from Shodan
        host_response = requests.get(host_url, timeout=60)
        host_info = host_response.json()
        
        domain_info = host_info.get('domains', [])
        hostname_info = host_info.get('hostnames', [])
        tags = domain_info + hostname_info + [shodan_query]+ ['shodan']
        
        # Insert into MongoDB (update or create)
        if targets_collection.find_one({"domain": f"{host}:{ports}"}):
            return  # Skip if domain already exists

        new_target = {
            "domain": f"{host}:{ports}",
            "ports": [ports],
            "rootDomain": 'ip',
            "tag": tags,
            "createdAt": datetime.now(),
            "lastUpdate": datetime.now(),
            "in_public_ips": "n/a",
            "ip": "n/a",
            "record_id": "n/a",
            "type": "n/a",
            "zone_id": "n/a",
            "dns_content": "n/a",
            "totalVulnerability": 0,
            "totalSubDomains": 0
        }
        targets_collection.insert_one(new_target)
    
    except Exception as e:
        logger.exception(f"Error processing Shodan result for {result.get('ip_str')}: {str(e)}")      

@targets_bp.route('/shodan', methods=['POST'])
@token_required
def find_from_shodan():
    try:
        # Get the Shodan query from the request body
        shodan_query = request.json.get('shodanQuery')
        
        if not shodan_query:
            return jsonify({"error": "Missing 'shodanQuery' in the request body"}), 400

        # Create a new job for the Shodan query and return the response immediately
        response, job_id = create_shodan_job(shodan_query)

        # Perform the Shodan query in the background
        def background_task():
            try:
                execute_shodan_query(job_id, shodan_query)
            except Exception as e:
                logger.exception(f"Error executing Shodan query for job {job_id}: {str(e)}")
                # Update job status to failed if background task encounters error
                jobs_collection.update_one({"_id": ObjectId(job_id)}, {"$set": {"status": "failed"}})

        # Run the background task in a separate thread
        Thread(target=background_task).start()

        return response
    except Exception as e:
        logger.exception(f"Error in find_from_shodan: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Subfinder function
def run_subfinder(target):
    root_domain = target['domain']
    job_id = create_job(root_domain, target)

    try:
        # RUn subfinder for a root domain
        result = subprocess.run(
            ['subfinder', '-d', root_domain, '-silent'],
            capture_output=True,
            text=True
        )
        subdomains = result.stdout.splitlines()
        total_subdomains = len(subdomains)

        for subdomain in subdomains:
            # Check if subdomain is exist in database or not
            existing_target = targets_collection.find_one({"domain": subdomain})
            if existing_target:
                # Inherit tags from subdomain, remove 'wildcard' tag
                inherited_tags = [tag for tag in existing_target.get('tag', []) if tag != 'wildcard']
            else:
                # Else: Pick inherited_tags from root domain
                inherited_tags = [tag for tag in target.get('tag', []) if tag != 'wildcard']
                # Add new subdomain into mongo
                insert_subdomain(subdomain, root_domain, inherited_tags)

        
        update_job_status(job_id, "done", total_subdomains)

    except Exception as e:
        print(f"Error running subfinder: {e}")
        
        update_job_status(job_id, "failed")

# Func for running subfinder in separated thread
def run_subfinder_thread(targets):
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(run_subfinder, target) for target in targets]
        concurrent.futures.wait(futures)

@targets_bp.route('/subfinder', methods=['POST'])
@token_required
def find_subdomains():
    data = request.json
    target_ids = data.get('targets', [])

    # Get list of target from target_ids
    targets = [targets_collection.find_one({"_id": ObjectId(target_id)}) for target_id in target_ids]

    # Run subfinder in thread
    threading.Thread(target=run_subfinder_thread, args=(targets,)).start()

    return jsonify({"message": "Subdomain initiated, visit Job Manager for detail"}), 200

# Func insert subdomain into MongoDB
def insert_subdomain(subdomain, root_domain, inherited_tags):
    new_subdomain = {
        "domain": subdomain,
        "rootDomain": root_domain,
        "tag": inherited_tags,  # Kế thừa tag cha, đã lọc 'wildcard'
        "ports": [],
        "createdAt": datetime.now(),
        "lastUpdate": datetime.now(),
        "in_public_ips": "n/a",
        "ip": "n/a",
        "record_id": "n/a",
        "type": "n/a",
        "zone_id": "n/a",
        "dns_content": "n/a",
        "totalVulnerability": 0,
        "totalSubDomains": 0
    }

    targets_collection.insert_one(new_subdomain)

# Func for creating new job trong MongoDB
def create_job(root_domain, target):
    job = {
        "typeJob": "subfinder",
        "status": "running",
        "target": root_domain,
        "tag": target.get('tag', []),
        "createdAt": datetime.now(),
        "totalFinding": 0
    }
    job_id = jobs_collection.insert_one(job).inserted_id
    return job_id

# Func for updating job status
def update_job_status(job_id, status, total_subdomains=0):
    update_fields = {
        "status": status
    }
    if status == "done":
        update_fields["totalFinding"] = total_subdomains

    jobs_collection.update_one(
        {"_id": job_id},
        {"$set": update_fields}
    )



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

def run_nuclei_scan(target_domain, job_id):

    command = ['nuclei', '-u', target_domain,'-id', 'tech-detect', '-j']
    
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        total_findings = 0

        for line in iter(process.stdout.readline, b''):
            if line:
                try:
                    clean_line = remove_ansi_escape_sequences(line.decode('utf-8')).strip()
                    result = json.loads(clean_line)
                    #extract data from result scan

                    severity = result.get('info', {}).get('severity', '').lower()
                    template_id = result.get('template-id', '')
                    tags = result.get('info', {}).get('tags', [])
                    extracted_results = result.get('extracted-results', [])
                    affected_Item = result.get('matched-at', '')

                    if severity in ["critical", "high", "medium", "low"]:
                        hash_value = get_md5_hash(template_id + affected_Item)
                        existing_vulnerability = vulnerabilities_collection.find_one({"hash": hash_value})
    
                        if not existing_vulnerability:
                            # If hash is not exists, put the vulnerability into the vulnerability collection 

                            vulnerabilities_collection.insert_one({
                                "id": template_id,
                                "severity": severity,
                                "affectedItem": affected_Item,
                                "createdAt": datetime.now(),
                                "domain": target_domain,
                                "hash": get_md5_hash(template_id+affected_Item)
                            })
                            total_findings += 1
                            targets_collection.update_one({"domain": target_domain}, {"$inc": {"totalFinding": 1}})
                        else:
                            continue

                    elif severity == "info":
                        if template_id == "tech-detect":
                            tech_tag = result.get('matcher-name', '')
                            targets_collection.update_one({"domain": target_domain}, {"$addToSet": {"tag": tech_tag}})
                            print("tech-detect")
                        if 'tech' in tags and len(extracted_results) > 0:
                            # collect wordpress information
                            if "wordpress" in template_id:
                                tech_tag = template_id + str(extracted_results)
                                targets_collection.update_one({"domain": target_domain}, {"$addToSet": {"tag": tech_tag}})
                                print("add wordpress")
                            else:
                                for result in extracted_results:
                                    tech_tag = result
                                    targets_collection.update_one({"domain": target_domain}, {"$addToSet": {"tag": tech_tag}})
                                    print("add extracted_results")
                except json.JSONDecodeError:
                    print(f"Failed to decode JSON: {clean_line}")
                    continue
        
        process.stdout.close()
        process.stderr.close()
        process.wait()

        # Update job status to 'done' and set total findings
        jobs_collection.update_one({"_id": ObjectId(job_id)}, {"$set": {"status": "done", "totalFinding": total_findings}})

    except Exception as e:
        print(f"An error occurred while running nuclei scan for {target_domain}: {e}")
        jobs_collection.update_one(
            {"_id":  ObjectId(job_id)},
            {
            "$set": {
                "status": "failed"
            }
            }
        )

@targets_bp.route('/nuclei', methods=['POST'])
@token_required
def nuclei_scan():
    data = request.json
    target_ids = data.get('ids', [])

    def execute_scans():
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for target_id in target_ids:
                target = targets_collection.find_one({"_id": ObjectId(target_id)})

                if target:
                    job = {
                        "typeJob": "nuclei",
                        "status": "running",
                        "target": target['domain'],
                        "tag": [],
                        "createdAt": datetime.now(),
                        "totalFinding": 0
                    }
                    job_id = jobs_collection.insert_one(job).inserted_id
                    futures.append(executor.submit(run_nuclei_scan, target['domain'], str(job_id)))

    scan_thread = Thread(target=execute_scans)
    scan_thread.start()
    
    return jsonify({"message": "Nuclei scan initiated"}), 200

def run_nmap_scan(target_domain, job_id):
    command = ['nmap', '-oX', '-', '-p1-10000,16889,30000-32000', '--open', '--min-rate=80', target_domain]
    
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            print(f"Nmap scan failed for {target_domain}: {stderr.decode('utf-8')}")
            return

        total_open_ports = 0
        result = stdout.decode('utf-8')

        # Parse Nmap XML output
        root = ET.fromstring(result)

        # Check if the host is down based on <hosts up="0" down="1" total="1"/> in the XML output
        runstats = root.find('runstats')
        hosts_info = runstats.find('hosts')

        targets_collection.update_one(
            {"domain": target_domain}, 
            {
                "$set": {"ports": [], "lastUpdate": datetime.now()}
            }
        )

        if hosts_info.get('up') == '0':
            print(f"Host {target_domain} is down.")
            targets_collection.update_one({"domain": target_domain}, {"$set": {"ports": "host_down","lastUpdate": datetime.now()}})
            jobs_collection.update_one({"_id": ObjectId(job_id)}, {"$set": {"status": "done", "totalFinding": 0}})
            return
        else:
            # If host is up, check for open ports
            for host in root.findall('host'):
                for port in host.findall('.//port'):
                    port_id = port.get('portid')
                    str_port_id = str(port_id)
                    total_open_ports += 1

                    service = port.find('service')
                    service_name = service.get('name', 'unknown') if service is not None else 'unknown'

                    # Update ports in MongoDB
                    targets_collection.update_one(
                        {"domain": target_domain}, 
                        {
                            "$addToSet": {"ports": f"{str_port_id}: {service_name}"},
                            "$set": {"lastUpdate": datetime.now()}
                        }
                        
                    )
                    print(f"Open port found: {str_port_id} ({service_name})")

            # Update job status to 'done' and set total open ports
            jobs_collection.update_one({"_id": ObjectId(job_id)}, {"$set": {"status": "done", "totalFinding": total_open_ports}})

    except Exception as e:
        print(f"An error occurred while running nmap scan for {target_domain}: {e}")
        jobs_collection.update_one(
            {"_id": ObjectId(job_id)},
            {"$set": {"status": "failed"}}
        )

@targets_bp.route('/nmap', methods=['POST'])
@token_required
def nmap_scan():
    data = request.json
    target_ids = data.get('ids', [])
    # print("target_ids: "+str(target_ids))

    def execute_scans():
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for target_id in target_ids:
                target = targets_collection.find_one({"_id": ObjectId(target_id)})
                # print ("target: {0}".format(target))
                if target:
                    job = {
                        "typeJob": "nmap",
                        "status": "running",
                        "target": target['domain'],
                        "tag": [],
                        "createdAt": datetime.now(),
                        "totalFinding": 0
                    }
                    job_id = jobs_collection.insert_one(job).inserted_id
                    futures.append(executor.submit(run_nmap_scan, target['domain'], str(job_id)))
            # Optional: if you want to ensure all tasks complete before moving on
            # concurrent.futures.wait(futures)

    # Tạo một luồng mới để thực thi các lệnh quét
    scan_thread = Thread(target=execute_scans)
    scan_thread.start()
    
    return jsonify({"message": "Nmap scan initiated"}), 200

# Func for reverse ip lookup
def reverse_dns_lookup(ip):
    try:
        domain, _, _ = socket.gethostbyaddr(ip)
        return domain
    except socket.herror:
        return None
# Func API for reverse dns
@targets_bp.route('/reverse-dns', methods=['POST'])
@token_required
def reverse_dns_scan():
    data = request.json
    target_ids = data.get('ids', [])

    def execute_scans():
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for target_id in target_ids:
                target = targets_collection.find_one({"_id": ObjectId(target_id)})
                if target:
                    ip_address = target.get('domain').split(':')[0]
                    if ip_address:
                        # Tạo job trong jobs_collection
                        job = {
                            "typeJob": "reverse_dns",
                            "status": "running",
                            "target": ip_address,
                            "tag": [],
                            "createdAt": datetime.now(),
                            "totalFinding": 0
                        }
                        job_id = jobs_collection.insert_one(job).inserted_id
                        
                        futures.append(executor.submit(run_reverse_dns_scan, target, ip_address, str(job_id)))

    scan_thread = Thread(target=execute_scans)
    scan_thread.start()

    return jsonify({"message": "Reverse DNS scan initiated"}), 200

def run_reverse_dns_scan(target, ip_address, job_id):
    
    domain = reverse_dns_lookup(ip_address)
    
    found_domain = False
    
    if domain:
        found_domain = True
        # Check if domain is not found in tag array
        if 'tag' not in target:
            target['tag'] = []

        if domain not in target['tag']:
            target['tag'].append(domain)

        targets_collection.update_one(
            {"_id": target['_id']},
            {"$set": {"tag": target['tag']}}
        )
    # Update job status
    jobs_collection.update_one(
        {"_id": ObjectId(job_id)},
        {
            "$set": {
                "status": "done",
                "totalFinding": 1 if found_domain else 0,
                "finishedAt": datetime.now()
            }
        }
    )
