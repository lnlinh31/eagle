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
from HelperFunction import *

mongo_uri = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
client = MongoClient(mongo_uri)
db = client['eagle_db']
targets_collection = db['targets']
jobs_collection = db['jobs']

def check_open_ports():
    # Chỉ lấy những document có field 'ports' và field này không rỗng
    targets_with_open_ports = targets_collection.find({"ports": {"$exists": True, "$ne": [], "$ne": "host_down"}})
    
    # Define a set of ports to ignore
    ignored_ports = {'80: http', '443: https'}
    
    for target in targets_with_open_ports:
        domain = target.get('domain')
        open_ports = target.get('ports', [])
        
        # Check if open_ports is a subset of ignored_ports
        if set(open_ports).issubset(ignored_ports):
            print(f"Skipping target: {domain}, only common ports open: {open_ports}")
            continue  # Skip this target if its ports are only '80: http' and '443: https'

        tag = target.get('tag', [])
        # Otherwise, send alert for the target
        message = f"Target: {domain} with {tag} tag has open ports: {open_ports}"

        # Send message to Slack
        slack_data = {'text': message}
        response = requests.post(SLACK_WEBHOOK_URL, json=slack_data)
        
        if response.status_code == 200:
            print(f"Notification sent for {domain}")
            time.sleep(5)
        else:
            print(f"Failed to send notification for {domain}: {response.status_code}")

def check_dangling_record_dns():
    # Tìm các object thỏa mãn điều kiện
    dangling_records = targets_collection.find({
        "in_public_ips": "no",
        "type": {"$in": ["A", "CNAME"]},
        "tag": {"$nin": ["keep_record"]}
    })
    
    for record in dangling_records:
        domain = record.get('domain')
        source_provider = record.get('source_provider')
        record_type = record.get('type')
        dns_content = record.get('dns_content')
        
        # Tạo message thông báo
        message = f"Found following record DNS on {source_provider} that potentially dangling: {domain} + {record_type} + {dns_content}"
        
        # Gửi thông báo ra Slack
        slack_data = {'text': message}
        response = requests.post(SLACK_WEBHOOK_URL, json=slack_data)
        
        if response.status_code == 200:
            print(f"Notification sent for {domain}")
            time.sleep(5)
        else:
            print(f"Failed to send notification for {domain}: {response.status_code}")

def crawl_public_ip():
    public_ips = []

    # Crawl ip from AWS
    try:
        # Get all AWS regions
        regions = get_all_aws_regions()

        for region in regions:
            print(f"Crawling region: {region}")

            # Initialize clients for each region
            ec2_client = boto3.client('ec2', region_name=region,aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

            # EC2 Instances
            try:
                ec2_response = ec2_client.describe_instances()
                for reservation in ec2_response['Reservations']:
                    for instance in reservation['Instances']:
                        public_ip = instance.get('PublicIpAddress')
                        if public_ip:
                            public_ips.append(public_ip)
                            # print(f"EC2 Public IP: {public_ip}")
                            targets_collection.update_one(
                                {"domain": public_ip},
                                {"$set": {"domain": public_ip, "tag": ["aws"], "lastUpdate": datetime.now()}, 
                                "$setOnInsert": {
                                    "rootDomain": "ip", 
                                    "createdAt": datetime.now(),                
                                    "in_public_ips": "n/a",
                                    "ports": "host_down",
                                    "ip": "n/a",
                                    "record_id": "n/a",
                                    "type": "n/a",
                                    "zone_id": "n/a",
                                    "dns_content": 'n/a',
                                    "source_provider": "n/a",
                                    "totalVulnerability": 0, 
                                    "totalSubDomains": 0
                                }},
                                upsert=True
                            )
            except Exception as e:
                print(f"Error fetching EC2 instances in region {region}: {e}")

            # Network Interfaces
            try:
                ni_response = ec2_client.describe_network_interfaces()
                for interface in ni_response['NetworkInterfaces']:
                    association = interface.get('Association', {})
                    public_ip = association.get('PublicIp')
                    if public_ip:
                        public_ips.append(public_ip)
                        # print(f"Network Interface Public IP: {public_ip}")
                        targets_collection.update_one(
                            {"domain": public_ip},
                            {"$set": {"domain": public_ip, "tag": ["aws"],"lastUpdate": datetime.now()},"$setOnInsert": {
                                "rootDomain": "ip", 
                                "createdAt": datetime.now(), 
                                "in_public_ips": "n/a",
                                "ports": "host_down",
                                "ip": "n/a",
                                "record_id": "n/a",
                                "type": "n/a",
                                "zone_id": "n/a",
                                "dns_content": 'n/a',
                                "source_provider": "n/a",
                                "totalVulnerability": 0, 
                                "totalSubDomains": 0
                            }},
                            upsert=True
                        )
            except Exception as e:
                print(f"Error fetching network interfaces in region {region}: {e}")

    except (NoCredentialsError, PartialCredentialsError) as e:
        print(f"Error fetching AWS data: {str(e)}")
        return
    
    # Crawl ip from Digital Ocean
    try:
        digital_ocean_public_ips = crawl_digital_ocean_public_ips()
        
        if not digital_ocean_public_ips:
            print("No public IPs found from Digital Ocean.")
            return
        
        for public_ip in digital_ocean_public_ips:
            
            try:
                targets_collection.update_one(
                    {"domain": public_ip},
                    {"$set": {"domain": public_ip, "tag": ["digital_ocean"],"lastUpdate": datetime.now()}, 
                    "$setOnInsert": {
                        "rootDomain": "ip", 
                        "createdAt": datetime.now(), 
                        "in_public_ips": "n/a",
                        "ports": "host_down",
                        "ip": "n/a",
                        "record_id": "n/a",
                        "type": "n/a",
                        "zone_id": "n/a",
                        "dns_content": 'n/a',
                        "source_provider": "n/a",
                        "totalVulnerability": 0, 
                        "totalSubDomains": 0
                    }},
                    upsert=True
                )
                print(f"Successfully updated/inserted {public_ip} from Digital Ocean.")
            except PyMongoError as e:
                print(f"Error while updating MongoDB for IP {public_ip}: {e}")
    
    except Exception as e:
        print(f"Unexpected error occurred during crawl_public_ip: {e}")

    # print(f"Total collected public IPs: {len(public_ips)}")
  
    slack_data = {'text': f"Successfully collect {len(public_ips)} ip from AWS & {len(digital_ocean_public_ips)} ip from Digital Ocean"}
    requests.post(SLACK_WEBHOOK_URL, json=slack_data)
    
    return public_ips

def run_nmap():
    targets = targets_collection.find({"rootDomain": "ip"})
    target_ids = [str(target['_id']) for target in targets]
    # print(f"Found {len(target_ids)} targets")

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

    slack_data = {'text': "Successfully scan nmap for all targets"}
    requests.post(SLACK_WEBHOOK_URL, json=slack_data)

def crawl_domain_from_all():
    """ Hàm chính để crawl tất cả các domain từ các cloud providers """
    crawl_domain_from_route53()
    crawl_domain_from_cloudflare()
    crawl_domain_from_digitalocean()

    slack_data = {'text': f"Successfully collect domain from cloudflare, route53 aws, digital ocean and find dangling records"}
    requests.post(SLACK_WEBHOOK_URL, json=slack_data)

def crawl_bugbounty_domain():
    url = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/domains.txt"
    
    try:
        # Gửi request để lấy dữ liệu domain
        response = requests.get(url)
        response.raise_for_status()  # Kiểm tra nếu request bị lỗi

        # Đọc nội dung và tách các dòng
        domains = response.text.strip().splitlines()

        for domain in domains:
            # Kiểm tra nếu domain đã tồn tại trong database
            if targets_collection.find_one({"domain": domain}):
                continue
            
            # Tạo document theo định dạng yêu cầu
            document = {
                "domain": domain,
                "ports": ["443"],  # Mặc định port là 443
                "rootDomain": "self",  # Cài đặt giá trị rootDomain mặc định là 'self'
                "tag": ["bugbounty"],  # Tag mặc định là 'bugbounty'
                "createdAt": datetime.utcnow(),  # Thời gian hiện tại theo UTC
                "lastUpdate": datetime.utcnow(),
                "in_public_ips": "n/a",
                "ip": "n/a",
                "record_id": "n/a",
                "type": "n/a",
                "zone_id": "n/a",
                "dns_content": "n/a",
                "totalVulnerability": 0,  # Mặc định là 0
                "totalSubDomains": 0  # Mặc định là 0
            }

            # Thêm document vào collection MongoDB
            targets_collection.insert_one(document)
        
        print(f"Successfully inserted {len(domains)} domains into MongoDB.")
    
    except requests.RequestException as e:
        print(f"Error fetching domains: {e}")
    except pymongo.errors.PyMongoError as e:
        print(f"MongoDB error: {e}")
