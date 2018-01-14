import argparse
import boto3
from botocore.exceptions import ClientError
import time

# TODO maybe move constants to separate file?
BUCKET_NAME = "IP-flow-logs-561"
ROOT_LOGS_FOLDER = "logs"
ROOT_QUERY_FOLDER = "queries"
REJECTED_SSH_QUERY = "SELECT sourceaddress, count(*) cnt FROM vpc_flow_logs WHERE action = 'REJECT' AND protocol = 6 AND destinationport = 22 GROUP BY sourceaddress ORDER BY cnt desc LIMIT 100"

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

# Call S3 to list current buckets
response = s3.list_buckets()

# Get a list of all bucket names from the response
buckets = [bucket['Name'] for bucket in response['Buckets']]

# Print out the bucket list
# print("Bucket List: %s" % buckets)
# print(response);

# Create bucket for flow logs if it doesn't already exist
# TODO: ensure this bucket has proper policy!
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

# Upload formatted flow logs to bucket in new folder
# s3.upload_file(filename, BUCKET_NAME, path)
# print("Uploaded " + filename + " to bucket in " + path)

## Athena stuff
print("Querying bucket for potential SSH attack...")
## Test running a query I know will work for an existing table and database
response = athena.start_query_execution(
    QueryString=REJECTED_SSH_QUERY,
    # ClientRequestToken='string',
    QueryExecutionContext={
        'Database': '561database'
    },
    ResultConfiguration={
        'OutputLocation': "s3://" + BUCKET_NAME + "/" + ROOT_QUERY_FOLDER + "/"
    }
)

# TODO waiters for Athena are currently being implemented in boto, until this feature is available,
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
    # NextToken='string',
    # MaxResults=123
)

print(results)
