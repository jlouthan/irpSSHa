import argparse
import boto3
from botocore.exceptions import ClientError
import time

import requests
import json

# TODO maybe move constants to separate file?
# Name of S3 bucket and folders to store logs and queries
BUCKET_NAME = "IP-flow-logs-561"
DB_NAME = "flowlogsdb"
TABLE_NAME = "flow_logs_561"
ROOT_LOGS_FOLDER = "logs"
QUERY_LOCATION = "s3://" + BUCKET_NAME + "/queries/"
# Number of failed ssh attempts required to identify source IP as potential attacker
ATTEMPT_THRESHOLD = 2
# Max number of source IPs to identify at once
LIMIT = 100
# Query string to run on the data to identify potential attackers
REJECTED_SSH_QUERY = "SELECT sourceaddress, count(*) cnt FROM " + TABLE_NAME + " \
	WHERE action = 'REJECT' AND protocol = 6 AND destinationport = 22 \
	GROUP BY sourceaddress HAVING count(*) >= " + str(ATTEMPT_THRESHOLD) + " \
	ORDER BY cnt desc LIMIT " + str(LIMIT)

# TODO make this output the perfect thing: https://docs.python.org/2/library/argparse.html
parser = argparse.ArgumentParser(description='Test Script for Final Project')
parser.add_argument('filename', metavar='filename', type=str, 
	help='file containing formatted IP flow logs')
# parser.add_argument('--sum', dest='accumulate', action='store_const',
#                     const=sum, default=max,
#                     help='sum the integers (default: find the max)')

args = parser.parse_args()
filename = args.filename
epoch_time = int(time.time())
new_folder = "uploaded-logs-" + str(epoch_time)
path = ROOT_LOGS_FOLDER + "/" + new_folder + "/" + filename;

# Create an S3 client
s3 = boto3.client('s3')
athena = boto3.client('athena', 'us-east-1')

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

## Athena stuff

#TODO move this function into other file (helper class)!
# Runs Athena query for default database and returns results sychronously
def run_query(query_string, database=None):
	execution_context = {'Database': database}
	# execution_context = {'Database': database} if database else {'Database': ''}
	if database:
		response = athena.start_query_execution(
			QueryString=query_string,
			QueryExecutionContext={
				'Database': database
			},
			ResultConfiguration={
				'OutputLocation': QUERY_LOCATION
			}
		)
	else:
		response = athena.start_query_execution(
			QueryString=query_string,
			ResultConfiguration={
				'OutputLocation': QUERY_LOCATION
			}
		)
	# Waiters for Athena are currently being implemented in boto, until this feature is available,
	# we need to. https://github.com/boto/boto3/issues/1212
	queryId = response['QueryExecutionId']
	# TODO move the query states into constants
	state = 'RUNNING'

	while state == 'RUNNING':
		response = athena.get_query_execution(
			QueryExecutionId=queryId
		)
		state = response['QueryExecution']['Status']['State']

	if state != 'SUCCEEDED':
		print("Error running query. Stopped execution with state " + state)
		quit()

	results = athena.get_query_results(
    	QueryExecutionId=queryId
	)
	return results


run_query("CREATE DATABASE IF NOT EXISTS " + DB_NAME)
print("Database exists")

#TODO instead of dropping the existing table, should we create a new one for each time the script runs??
run_query("DROP TABLE " + TABLE_NAME, DB_NAME)

# print("Creating table in Athena db")
location = "'s3://" + BUCKET_NAME + "/" + ROOT_LOGS_FOLDER + "/" + new_folder + "/'"
# TODO move this constant out of this file
# TODO regex should probably be in constants file too
CREATE_TABLE_QUERY = "CREATE EXTERNAL TABLE IF NOT EXISTS " + TABLE_NAME + " (\
  ts string,\
  version int,\
  account string,\
  interfaceid string,\
  sourceaddress string,\
  destinationaddress string,\
  sourceport int,\
  destinationport int,\
  protocol int,\
  numpackets int,\
  numbytes int,\
  starttime string,\
  endtime string,\
  action string,\
  logstatus string\
)\
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.RegexSerDe'\
WITH SERDEPROPERTIES\
 ( \"input.regex\" = \"^([^ ]+)\\\\s+([0-9]+)\\\\s+([^ ]+)\\\\s+([^ ]+)\\\\s+([^ ]+)\\\\s+([^ ]+)\\\\s+([0-9]+)\\\\s+([0-9]+)\\\\s+([0-9]+)\\\\s+([0-9]+)\\\\s+([0-9]+)\\\\s+([0-9]+)\\\\s+([0-9]+)\\\\s+([^ ]+)\\\\s+([^ ]+)$\" )\
LOCATION " + location + ";"

results = run_query(CREATE_TABLE_QUERY, DB_NAME)

status_code = results["ResponseMetadata"]['HTTPStatusCode']
if status_code != 200:
	print("Table creation failed with status code " + str(status_code));
	quit()
	
print("Table exists")
print("Querying table/bucket for potential SSH attack...")
results = run_query(REJECTED_SSH_QUERY, DB_NAME)

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