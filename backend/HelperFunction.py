import os, jwt, requests
from pymongo import MongoClient
from config import SLACK_WEBHOOK_URL, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, DIGITAL_OCEAN_ACCESS_TOKEN, DIGITAL_OCEAN_API_URL_DROPLETS,DIGITAL_OCEAN_API_URL_LOAD_BALANCERS, DIGITAL_OCEAN_API_URL_FLOATING_IPS, CLOUDFLARE_ACCESS_TOKEN
from apscheduler.schedulers.background import BackgroundScheduler
import time
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from threading import Thread
import subprocess,re,json
import concurrent.futures
import xml.etree.ElementTree as ET
from bson import ObjectId
from datetime import datetime
import socket, tldextract, logging

mongo_uri = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
client = MongoClient(mongo_uri)
db = client['eagle_db']
targets_collection = db['targets']
jobs_collection = db['jobs']

########### logging setup###################################
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler('/var/log/gunicorn/error.log')
file_handler.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
###########################################################

# def check_open_ports():
#     # Chỉ lấy những document có field 'ports' và field này không rỗng
#     targets_with_open_ports = targets_collection.find({"ports": {"$exists": True, "$ne": [], "$ne": "host_down"}})
    
#     # Define a set of ports to ignore
#     ignored_ports = {'80: http', '443: https'}
    
#     for target in targets_with_open_ports:
#         domain = target.get('domain')
#         open_ports = target.get('ports', [])
        
#         # Check if open_ports is a subset of ignored_ports
#         if set(open_ports).issubset(ignored_ports):
#             print(f"Skipping target: {domain}, only common ports open: {open_ports}")
#             continue  # Skip this target if its ports are only '80: http' and '443: https'

#         tag = target.get('tag', [])
#         # Otherwise, send alert for the target
#         message = f"Target: {domain} with {tag} tag has open ports: {open_ports}"

#         # Send message to Slack
#         slack_data = {'text': message}
#         response = requests.post(SLACK_WEBHOOK_URL, json=slack_data)
        
#         if response.status_code == 200:
#             print(f"Notification sent for {domain}")
#             time.sleep(5)
#         else:
#             print(f"Failed to send notification for {domain}: {response.status_code}")

def get_all_aws_regions():
    """Get all AWS regions for EC2 service"""
    ec2 = boto3.client('ec2',region_name ='us-west-2',aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    regions = ec2.describe_regions()
    return [region['RegionName'] for region in regions['Regions']]

def get_digital_ocean_droplet_ips(headers):
    try:
        response = requests.get(DIGITAL_OCEAN_API_URL_DROPLETS, headers=headers)
        response.raise_for_status()  # Kiểm tra lỗi HTTP
        droplets = response.json().get('droplets', [])
        
        public_ips = []
        for droplet in droplets:
            networks = droplet.get('networks', {}).get('v4', [])
            for network in networks:
                if network.get('type') == 'public':
                    public_ips.append(network.get('ip_address'))
        
        return public_ips
    except requests.exceptions.RequestException as e:
        print(f"Error while fetching Droplet IPs: {e}")
        return []

def get_digital_ocean_load_balancer_ips(headers):
    try:
        response = requests.get(DIGITAL_OCEAN_API_URL_LOAD_BALANCERS, headers=headers)
        response.raise_for_status()  # Kiểm tra lỗi HTTP
        load_balancers = response.json().get('load_balancers', [])
        
        public_ips = []
        for lb in load_balancers:
            if 'ip' in lb:
                public_ips.append(lb['ip'])
        
        return public_ips
    except requests.exceptions.RequestException as e:
        print(f"Error while fetching Load Balancer IPs: {e}")
        return []

def get_digital_ocean_floating_ips(headers):
    try:
        response = requests.get(DIGITAL_OCEAN_API_URL_FLOATING_IPS, headers=headers)
        response.raise_for_status()  # Kiểm tra lỗi HTTP
        floating_ips = response.json().get('floating_ips', [])
        
        public_ips = [ip.get('ip') for ip in floating_ips if 'ip' in ip]
        
        return public_ips
    except requests.exceptions.RequestException as e:
        print(f"Error while fetching Floating IPs: {e}")
        return []

def crawl_digital_ocean_public_ips():
    headers = {
        "Authorization": f"Bearer {DIGITAL_OCEAN_ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }
    
    public_ips = []
    
    # Lấy public IPs từ Droplets
    droplet_ips = get_digital_ocean_droplet_ips(headers)
    public_ips.extend(droplet_ips)
    
    # Lấy public IPs từ Load Balancers
    load_balancer_ips = get_digital_ocean_load_balancer_ips(headers)
    public_ips.extend(load_balancer_ips)
    
    # Lấy public IPs từ Floating IPs
    floating_ips = get_digital_ocean_floating_ips(headers)
    public_ips.extend(floating_ips)
    
    return public_ips

# def crawl_public_ip():
#     public_ips = []

#     # Crawl ip from AWS
#     try:
#         # Get all AWS regions
#         regions = get_all_aws_regions()

#         for region in regions:
#             print(f"Crawling region: {region}")

#             # Initialize clients for each region
#             ec2_client = boto3.client('ec2', region_name=region,aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

#             # EC2 Instances
#             try:
#                 ec2_response = ec2_client.describe_instances()
#                 for reservation in ec2_response['Reservations']:
#                     for instance in reservation['Instances']:
#                         public_ip = instance.get('PublicIpAddress')
#                         if public_ip:
#                             public_ips.append(public_ip)
#                             # print(f"EC2 Public IP: {public_ip}")
#                             targets_collection.update_one(
#                                 {"domain": public_ip},
#                                 {"$set": {"domain": public_ip, "tag": "aws", "lastUpdate": datetime.now()}, 
#                                 "$setOnInsert": {
#                                     "rootDomain": "ip", 
#                                     "createdAt": datetime.now(),                
#                                     "in_public_ips": "n/a",
#                                     "ports": "host_down",
#                                     "ip": "n/a",
#                                     "record_id": "n/a",
#                                     "type": "n/a",
#                                     "zone_id": "n/a",
#                                     "dns_content": 'n/a',
#                                     "totalVulnerability": 0, 
#                                     "totalSubDomains": 0
#                                 }},
#                                 upsert=True
#                             )
#             except Exception as e:
#                 print(f"Error fetching EC2 instances in region {region}: {e}")

#             # Network Interfaces
#             try:
#                 ni_response = ec2_client.describe_network_interfaces()
#                 for interface in ni_response['NetworkInterfaces']:
#                     association = interface.get('Association', {})
#                     public_ip = association.get('PublicIp')
#                     if public_ip:
#                         public_ips.append(public_ip)
#                         # print(f"Network Interface Public IP: {public_ip}")
#                         targets_collection.update_one(
#                             {"domain": public_ip},
#                             {"$set": {"domain": public_ip, "tag": "aws","lastUpdate": datetime.now()},"$setOnInsert": {
#                                 "rootDomain": "ip", 
#                                 "createdAt": datetime.now(), 
#                                 "in_public_ips": "n/a",
#                                 "ports": "host_down",
#                                 "ip": "n/a",
#                                 "record_id": "n/a",
#                                 "type": "n/a",
#                                 "zone_id": "n/a",
#                                 "dns_content": 'n/a',
#                                 "totalVulnerability": 0, 
#                                 "totalSubDomains": 0
#                             }},
#                             upsert=True
#                         )
#             except Exception as e:
#                 print(f"Error fetching network interfaces in region {region}: {e}")

#     except (NoCredentialsError, PartialCredentialsError) as e:
#         print(f"Error fetching AWS data: {str(e)}")
#         return
    
#     # Crawl ip from Digital Ocean
#     try:
#         digital_ocean_public_ips = crawl_digital_ocean_public_ips()
        
#         if not digital_ocean_public_ips:
#             print("No public IPs found from Digital Ocean.")
#             return
        
#         for public_ip in digital_ocean_public_ips:
            
#             try:
#                 targets_collection.update_one(
#                     {"domain": public_ip},
#                     {"$set": {"domain": public_ip, "tag": "digital_ocean","lastUpdate": datetime.now()}, 
#                     "$setOnInsert": {
#                         "rootDomain": "ip", 
#                         "createdAt": datetime.now(), 
#                         "in_public_ips": "n/a",
#                         "ports": "host_down",
#                         "ip": "n/a",
#                         "record_id": "n/a",
#                         "type": "n/a",
#                         "zone_id": "n/a",
#                         "dns_content": 'n/a',
#                         "totalVulnerability": 0, 
#                         "totalSubDomains": 0
#                     }},
#                     upsert=True
#                 )
#                 print(f"Successfully updated/inserted {public_ip} from Digital Ocean.")
#             except PyMongoError as e:
#                 print(f"Error while updating MongoDB for IP {public_ip}: {e}")
    
#     except Exception as e:
#         print(f"Unexpected error occurred during crawl_public_ip: {e}")

#     # print(f"Total collected public IPs: {len(public_ips)}")
  
#     slack_data = {'text': f"Successfully collect {len(public_ips)} ip from AWS & {len(digital_ocean_public_ips)} ip from Digital Ocean"}
#     requests.post(SLACK_WEBHOOK_URL, json=slack_data)
    
#     return public_ips

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

# def run_nmap():
#     targets = targets_collection.find({"rootDomain": "ip"})
#     target_ids = [str(target['_id']) for target in targets]
#     # print(f"Found {len(target_ids)} targets")

#     def execute_scans():
#         with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
#             futures = []
#             for target_id in target_ids:
#                 target = targets_collection.find_one({"_id": ObjectId(target_id)})
#                 # print ("target: {0}".format(target))
#                 if target:
#                     job = {
#                         "typeJob": "nmap",
#                         "status": "running",
#                         "target": target['domain'],
#                         "tag": [],
#                         "createdAt": datetime.now(),
#                         "totalFinding": 0
#                     }
#                     job_id = jobs_collection.insert_one(job).inserted_id
#                     futures.append(executor.submit(run_nmap_scan, target['domain'], str(job_id)))
#             # Optional: if you want to ensure all tasks complete before moving on
#             # concurrent.futures.wait(futures)

#     # Tạo một luồng mới để thực thi các lệnh quét
#     scan_thread = Thread(target=execute_scans)
#     scan_thread.start()

#     slack_data = {'text': "Successfully scan nmap for all targets"}
#     requests.post(SLACK_WEBHOOK_URL, json=slack_data)

########################## CRAWL DOMAIN FROM CLOUDFLARE & AWS & ROUTE 53 ########

CLOUDFLARE_API_URL_ZONES = "https://api.cloudflare.com/client/v4/zones"
CLOUDFLARE_API_URL_DNS_RECORDS = "https://api.cloudflare.com/client/v4/zones/{}/dns_records"

def get_all_zones_from_cloudflare(headers):
    """ Lấy danh sách tất cả các zones từ Cloudflare """
    zones = []
    try:
        page = 1
        while True:
            response = requests.get(f"{CLOUDFLARE_API_URL_ZONES}?page={page}", headers=headers)
            response.raise_for_status()
            data = response.json()
            zones.extend(data['result'])
            if page >= data['result_info']['total_pages']:
                break
            page += 1
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching zones from Cloudflare: {e}")
    
    return zones

def get_dns_records_from_zone(zone_id, headers):
    """ Lấy tất cả các DNS records (A và CNAME) từ một zone nhất định """
    dns_records = []
    try:
        page = 1
        while True:
            response = requests.get(f"{CLOUDFLARE_API_URL_DNS_RECORDS.format(zone_id)}?page={page}&per_page=100&type=A,CNAME", headers=headers)
            response.raise_for_status()
            data = response.json()
            dns_records.extend(data['result'])
            if page >= data['result_info']['total_pages']:
                break
            page += 1
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching DNS records from zone {zone_id}: {e}")
    
    return dns_records

def check_ip_exists_in_public_ips(ip):
    """ Kiểm tra IP đã tồn tại trong targets_collection hay chưa """
    try:
        result = targets_collection.find_one({"domain": ip})
        if result:
            return True
        return False
    except PyMongoError as e:
        logger.error(f"MongoDB error while checking IP {ip}: {e}")
        return False

def resolve_cname_to_ip(cname_domain):
    """ Phân giải domain CNAME ra IP """
    try:
        ip = socket.gethostbyname(cname_domain)
        return ip
    except socket.error:
        logger.error(f"Error resolving CNAME domain {cname_domain}")
        return None

def get_root_domain(domain):
    """ Lấy giá trị root domain từ domain """
    ext = tldextract.extract(domain)
    root_domain = f"{ext.domain}.{ext.suffix}"
    return root_domain

def construct_full_domain(record_name, zone_name):
    """ Kiểm tra nếu record_name chưa phải là domain hoàn chỉnh, xây dựng domain hoàn chỉnh """
    if not record_name.endswith(zone_name):
        return f"{record_name}.{zone_name}"
    return record_name

def insert_domain_into_targets_collection(domain_data):
    """ Thêm domain mới vào MongoDB nếu chưa tồn tại """
    try:
        root_domain = get_root_domain(domain_data["domain"])
        
        targets_collection.update_one(
            {"domain": domain_data["domain"]},
            {
                "$set": {
                    "domain": domain_data["domain"],
                    "zone_id": domain_data["zone_id"],
                    "record_id": domain_data["record_id"],
                    "type": domain_data["type"],
                    "ip": domain_data["ip"],
                    "source_provider": domain_data["source_provider"],
                    "in_public_ips": domain_data["in_public_ips"],
                    "dns_content": domain_data["dns_content"],
                    "rootDomain": root_domain,
                    "lastUpdate": datetime.now(),
                },
                "$setOnInsert": {
                    "createdAt": datetime.now(),
                    "tag": [],
                    "ports": [],
                    "totalVulnerability": 0,
                    "totalSubDomains": 0
                }
            },
            upsert=True
        )
        logger.info(f"Inserted or updated domain {domain_data['domain']}")
    except PyMongoError as e:
        logger.error(f"MongoDB error while inserting domain {domain_data['domain']}: {e}")

def process_dns_records(dns_records, zone_id, zone_name, source_provider):
    """ Xử lý các DNS records để import vào MongoDB """
    for record in dns_records:
        domain = construct_full_domain(record['name'], zone_name)
        record_type = record['type']
        record_id = record['id']
        
        if record_type == 'A':
            ip = record['content']
            dns_content = 'n/a'
        elif record_type == 'CNAME':
            dns_content = record['content']
            # Phân giải domain CNAME ra IP nếu có
            ip = resolve_cname_to_ip(domain)
        
        if not ip:
            continue
        
        # Kiểm tra IP đã có trong public IPs hay chưa
        in_public_ips = "yes" if check_ip_exists_in_public_ips(ip) else "no"
        
        domain_data = {
            "domain": domain,
            "zone_id": zone_id,
            "record_id": record_id,
            "type": record_type,
            "ip": ip,
            "dns_content": dns_content,
            "in_public_ips": in_public_ips,
            "source_provider": source_provider
        }
        
        # Import vào MongoDB nếu domain chưa có
        insert_domain_into_targets_collection(domain_data)

def crawl_domain_from_cloudflare():
    """ Hàm chính để crawl tất cả các domain từ Cloudflare """
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }
    
    # 1. Lấy tất cả các zone từ Cloudflare
    zones = get_all_zones_from_cloudflare(headers)
    
    if not zones:
        logger.error("No zones found.")
        return
    
    # 2. Lặp qua từng zone để lấy tất cả các DNS records có type A và CNAME
    for zone in zones:
        zone_id = zone['id']
        zone_name = zone['name']
        logger.info(f"Processing zone {zone_id} ({zone_name})...")
        dns_records = get_dns_records_from_zone(zone_id, headers)
        
        if not dns_records:
            logger.info(f"No DNS records found for zone {zone_id}.")
            continue
        
        # 3. Xử lý và lưu các DNS records vào MongoDB
        process_dns_records(dns_records, zone_id, zone_name, source_provider='cloudflare')
    
    logger.info("Crawl completed.")

def get_all_domains_from_digitalocean():
    """ Lấy tất cả các domains từ DigitalOcean """
    url = "https://api.digitalocean.com/v2/domains"
    headers = {
        "Authorization": f"Bearer {DIGITALOCEAN_ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }
    
    domains = []
    try:
        while url:
            response = requests.get(url, headers=headers)
            data = response.json()
            domains.extend(data.get("domains", []))
            url = data.get("links", {}).get("pages", {}).get("next", None)  # Kiểm tra paginated results
    except requests.RequestException as e:
        logger.error(f"Error fetching domains from DigitalOcean: {e}")
    
    return domains

def get_dns_records_from_domain(domain_name):
    """ Lấy tất cả DNS records cho một domain từ DigitalOcean, chuẩn hóa để đồng bộ với process_dns_records """
    url = f"https://api.digitalocean.com/v2/domains/{domain_name}/records"
    headers = {
        "Authorization": f"Bearer {DIGITALOCEAN_ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }
    
    records = []
    try:
        while url:
            response = requests.get(url, headers=headers)
            data = response.json()
            for record in data.get("domain_records", []):
                # Chuẩn hóa record trả về với các field cần thiết
                normalized_record = {
                    'name': record['name'],       # Tên của record
                    'type': record['type'],       # Loại DNS record (A, CNAME, etc.)
                    'id': record['id'],           # ID của record
                    'content': record['data']     # IP cho A record hoặc domain cho CNAME
                }
                records.append(normalized_record)
            
            # Kiểm tra paginated results
            url = data.get("links", {}).get("pages", {}).get("next", None)
    except requests.RequestException as e:
        logger.error(f"Error fetching DNS records for domain {domain_name}: {e}")
    
    return records

def crawl_domain_from_digitalocean():
    """ Hàm chính để crawl tất cả các domain từ DigitalOcean """
    # 1. Lấy tất cả các domains
    domains = get_all_domains_from_digitalocean()
    
    if not domains:
        logger.error("No domains found in DigitalOcean.")
        return
    
    # 2. Lặp qua từng domain để lấy DNS records
    for domain in domains:
        domain_name = domain['name']
        logger.info(f"Processing domain {domain_name}...")
        dns_records = get_dns_records_from_domain(domain_name)
        
        if not dns_records:
            logger.info(f"No DNS records found for domain {domain_name}.")
            continue
        
        # 3. Xử lý và lưu các DNS records vào MongoDB
        process_dns_records(dns_records, domain_name, domain_name, source_provider='digitalocean')
    
    logger.info("Crawl completed for DigitalOcean.")

def get_all_public_hosted_zones():
    """ Lấy tất cả các hosted zones của AWS Route 53 với type public """
    try:
        client = boto3.client('route53')
        hosted_zones = client.list_hosted_zones()
        public_zones = [
            zone for zone in hosted_zones['HostedZones'] if not zone['Config']['PrivateZone']
        ]
        return public_zones
    except botocore.exceptions.BotoCoreError as e:
        logger.error(f"Error fetching hosted zones from AWS Route 53: {e}")
        return []

def get_dns_records_from_hosted_zone(zone_id):
    """ Lấy tất cả DNS records từ một zone của AWS Route 53, chuẩn hóa để đồng bộ với process_dns_records """
    client = boto3.client('route53')
    records = []
    try:
        paginator = client.get_paginator('list_resource_record_sets')
        for page in paginator.paginate(HostedZoneId=zone_id):
            for record in page['ResourceRecordSets']:
                # Chỉ xử lý các loại record có thể phân giải
                if record['Type'] in ['A', 'CNAME']:
                    # Lấy nội dung từ ResourceRecords
                    content = record['ResourceRecords'][0]['Value'] if record['ResourceRecords'] else None
                    
                    # Tạo id duy nhất bằng tổ hợp Name và Type
                    record_id = f"{record['Name']}_{record['Type']}"
                    
                    # Chuẩn hóa record trả về với các field cần thiết
                    normalized_record = {
                        'name': record['Name'].rstrip('.'),  # Loại bỏ dấu '.' ở cuối
                        'type': record['Type'],              # Loại DNS record (A, CNAME)
                        'id': record_id,                     # Tạo ID duy nhất
                        'content': content                   # Nội dung: IP hoặc CNAME domain
                    }
                    records.append(normalized_record)
    except botocore.exceptions.BotoCoreError as e:
        logger.error(f"Error fetching DNS records for zone {zone_id}: {e}")
    
    return records

def crawl_domain_from_route53():
    """ Hàm chính để crawl tất cả các public hosted zones từ AWS Route 53 """
    # 1. Lấy tất cả các public zones
    hosted_zones = get_all_public_hosted_zones()
    
    if not hosted_zones:
        logger.error("No public hosted zones found in AWS Route 53.")
        return
    
    # 2. Lặp qua từng hosted zone để lấy DNS records
    for zone in hosted_zones:
        zone_id = zone['Id'].split('/')[-1]  # Lấy zone ID
        zone_name = zone['Name']
        logger.info(f"Processing zone {zone_id} ({zone_name})...")
        dns_records = get_dns_records_from_hosted_zone(zone_id)
        
        if not dns_records:
            logger.info(f"No DNS records found for zone {zone_id}.")
            continue
        
        # 3. Xử lý và lưu các DNS records vào MongoDB
        process_dns_records(dns_records, zone_id, zone_name, source_provider='route53')
    
    logger.info("Crawl completed for AWS Route 53.")

# def crawl_domain_from_all():
#     """ Hàm chính để crawl tất cả các domain từ các cloud providers """
#     crawl_domain_from_route53()
#     crawl_domain_from_cloudflare()
#     crawl_domain_from_digitalocean()

#     slack_data = {'text': f"Successfully collect domain from cloudflare, route53 aws, digital ocean and find dangling records"}
#     requests.post(SLACK_WEBHOOK_URL, json=slack_data)
