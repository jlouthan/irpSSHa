import argparse
import boto3
from botocore.exceptions import ClientError
import time
import requests
import json

import athena_helper

# Name of S3 bucket and folders to store logs and queries
BUCKET_NAME = "IP-flow-logs-561"
ROOT_LOGS_FOLDER = "logs"

# TODO make this output the perfect thing: https://docs.python.org/2/library/argparse.html
parser = argparse.ArgumentParser(description='Test Script for Final Project')
parser.add_argument('filename', metavar='filename', type=str, 
	help='file containing formatted IP flow logs')

args = parser.parse_args()
filename = args.filename
epoch_time = int(time.time())
new_folder = "uploaded-logs-" + str(epoch_time)
path = ROOT_LOGS_FOLDER + "/" + new_folder + "/" + filename;

# Create an S3 client
s3 = boto3.client('s3')
athena_helper.athena = boto3.client('athena', 'us-east-1')

# Create bucket for flow logs if it doesn't already exist
while True:
	try:
		existing = s3.head_bucket(Bucket=BUCKET_NAME)
	except ClientError as e:
		if e.response['Error']['Code'] == "404":
			print("Bucket does not exist, creating bucket...")
			s3.create_bucket(Bucket=BUCKET_NAME)
		else:
			print("Unexpected error checking for bucket existence")
			quit()
	else:
		print("Bucket exists")
		break

#Upload formatted flow logs to bucket in new folder
s3.upload_file(filename, BUCKET_NAME, path)
print("Uploaded " + filename + " to bucket in " + path)

# Athena Stuff: Ensure db and table exist, export flow data from S3 into the table, 
# then query to get potential SSH attacker data

athena_helper.create_db(BUCKET_NAME)
print("Database exists")

# Location in S3 of the data to import into the Athena table (the stuff we just uploaded)
location = "'s3://" + BUCKET_NAME + "/" + ROOT_LOGS_FOLDER + "/" + new_folder + "/'"
status_code = athena_helper.create_table(location, BUCKET_NAME)
if status_code != 200:
	print("Table creation failed with status code " + str(status_code));
	quit()

print("Table exists")

print("Querying table/bucket for potential SSH attack...")
results = athena_helper.get_potential_attacks(BUCKET_NAME)

##TODO !! Move this into separate file/class
BASE_URL = "https://www.abuseipdb.com/"
API_KEY = "TOtnbGPgvX0VlEh4DcY7rPBGG7fV2nkcJ4LKnZXr"
DAYS = 60
BRUTE_FORCE_CAT = 18
SSH_CAT = 22
# Given a source IP address, queries the AbuseIPDB API and returns the number of times the IP
# has been reported in the last 60 days, and the number of those reports that were tagged with 
# the "ssh" or "brute force" categories, or both
def query_abuse_ip_db(source_ip):
	payload = {'key': API_KEY, "days": DAYS}
	res = requests.get(BASE_URL + "/check/" + source_ip + "/json", params=payload)
	num_reports = len(res.json())
	num_ssh_brute_force = 0
	country = ""
	for report in res.json():
		if "category" not in report:
			print(report)
		elif BRUTE_FORCE_CAT in report["category"] or SSH_CAT in report["category"]:
			num_ssh_brute_force += 1
			# Seems odd, but all reports have property country with the value of 
			# the country of the source IP
			country = report["country"]
	return num_reports, num_ssh_brute_force, country

source_ips = []
print("%-16s %-12s %-12s %-16s %-16s" % ("Source IP", "Count", "Reports", "SSH/BruteForce", "Country"))
for row in results['ResultSet']['Rows'][1:]:
	rowString = ""
	source_ip = row['Data'][0]['VarCharValue']
	# Query AbuseIPDB for number of times this ip has been reported
	# Get total number of times reported, as well as # for brute force and ssh category tags
	num_reports, num_ssh_brute_force, country = query_abuse_ip_db(source_ip)
	source_ips.append(row['Data'][0]['VarCharValue'])
	print("%-16s %-12s %-12s %-16s %-16s" % (row['Data'][0]['VarCharValue'], row['Data'][1]['VarCharValue'], str(num_reports), str(num_ssh_brute_force), country))

REPORT_COMMENT = "SSH Brute Force"

def report_ip(source_ip):
	payload = {'key': API_KEY, "ip": source_ip, "comment": REPORT_COMMENT, "category": str(BRUTE_FORCE_CAT) + "," + str(SSH_CAT)}
	res = requests.post(BASE_URL + "/report/json", params=payload)
	print(json.dumps(res.json(), indent=4))

# Provide prompts for user to optionally report IPs
print("\n To report one of these IPs, enter report <IP>. Type quit to exit.\n");
while True:
	user_input = raw_input(">")
	if user_input == "quit":
		quit()
	data = user_input.split()
	if len(data) == 2 and data[0] == "report":
		# Validate that a valid IP was passed
		if data[1] in source_ips:
			print("Valid input, reporting IP to AbuseIPDB...")
			report_ip(data[1])
		else:
			print("Invalid IP passed.")
	else:
		print("\nInvalid input.\nTo report one of these IPs, enter report <IP>. Type quit to exit.\n")