## Athena stuff

# athena needs to be initialized by module that imports this one
athena = None

# Constants
DB_NAME = "flowlogsdb"
TABLE_NAME = "flow_logs_561"
ROOT_QUERY_FOLDER = "queries"
# Number of failed ssh attempts required to identify source IP as potential attacker
ATTEMPT_THRESHOLD = 2
# Max number of source IPs to identify at once
LIMIT = 100

QUERY_RUN_STATE = "RUNNING"
QUERY_SUCCESS_STATE = "SUCCEEDED"

# Runs Athena query for default database and returns results sychronously
def run_query(query_string, bucket, database=None):
    execution_context = {'Database': database}
    # execution_context = {'Database': database} if database else {'Database': ''}
    if database:
        response = athena.start_query_execution(
            QueryString=query_string,
            QueryExecutionContext={
                'Database': database
            },
            ResultConfiguration={
                'OutputLocation': "s3://" + bucket + "/" + ROOT_QUERY_FOLDER + "/"
            }
        )
    else:
        response = athena.start_query_execution(
            QueryString=query_string,
            ResultConfiguration={
                'OutputLocation': "s3://" + bucket + "/" + ROOT_QUERY_FOLDER + "/"
            }
        )
    # Waiters for Athena are currently being implemented in boto, until this feature is available,
    # we need to. https://github.com/boto/boto3/issues/1212
    queryId = response['QueryExecutionId']
    state = QUERY_RUN_STATE

    while state == QUERY_RUN_STATE:
        response = athena.get_query_execution(
            QueryExecutionId=queryId
        )
        state = response['QueryExecution']['Status']['State']

    if state != QUERY_SUCCESS_STATE:
        print("Error running query. Stopped execution with state " + state)
        quit()

    res = athena.get_query_results(
        QueryExecutionId=queryId
    )
    return res

def create_db(bucket):
    run_query("CREATE DATABASE IF NOT EXISTS " + DB_NAME, bucket)

#Instead of dropping the existing table, should we create a new one for each time the script runs??
def create_table(data_location, bucket):
    run_query("DROP TABLE " + TABLE_NAME, bucket, DB_NAME)

    query_string = "CREATE EXTERNAL TABLE IF NOT EXISTS " + TABLE_NAME + " (\
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
    LOCATION " + data_location + ";"

    res = run_query(query_string, bucket, DB_NAME)
    status_code = res["ResponseMetadata"]['HTTPStatusCode']
    return status_code

def get_potential_attacks(bucket):
    # Query string to run on the data to identify potential attackers
    query_string = "SELECT sourceaddress, count(*) cnt FROM " + TABLE_NAME + " \
    WHERE action = 'REJECT' AND protocol = 6 AND destinationport = 22 \
    GROUP BY sourceaddress HAVING count(*) >= " + str(ATTEMPT_THRESHOLD) + " \
    ORDER BY cnt desc LIMIT " + str(LIMIT)

    res = run_query(query_string, bucket, DB_NAME)
    return res