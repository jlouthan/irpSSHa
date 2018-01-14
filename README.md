# Final Project for 561 Fall 2017:  Identifying and Reporting Potential SSH Attackers from IP Flow Logs (irpSSHa)

## Methodology

Given a file containing IP flow log data in the expected format (see [example](simple-example.txt)), save remotely in AWS S3 and 
use the data in S3 to run dynamic SQL queries to identify flows that indicate potential SSH attack attempts. 

## Requirements and Recommendations

It is recommended that the destination for the flows be secured enough to reject unauthorized SSH traffic. In particular, ssh login 
with username/password should be disabled and only whitelisted IPs should be allowed. For more information on securing hosts against 
ssh attackers, see ["Recommendations"](https://www.symantec.com/connect/articles/analyzing-malicious-ssh-login-attempts).

The user is required to have an AWS account with S3 and Athena enabled in the same region. AWS credentials should be stored 
locally in ~/.aws/credentials. [More info](https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration).

While the included AbuseIPDB API key is free to use, it is also recommended that any regular user registers for their own account 
to personalize the reports and avoid rate limiting. An account can be [created here](https://www.abuseipdb.com/register).

It is also recommended that the code be run inside a [virtual environment](http://docs.python-guide.org/en/latest/dev/virtualenvs/) or similar tool to isolate your Python environment. This project uses Python 2.7.9, although minimal work would be required to make compatible with Python 3.

## Running the script

First, ensure all dependencies are installed with `pip install -r requirements.txt`


Run `python attacks_from_data.py -h` for help and info about execution requirements.

### Output

The script will print updates about bucket, database, and table creation and querying. Once the Athena and AbuseIPDB queries are finished, you will see a table identifying potential SSH attackers:

```
(env)final-project jenniferlouthan$ python attacks_from_data.py flow-logs-example.txt 
Bucket exists
Uploaded flow-logs-example.txt to bucket in logs/uploaded-logs-1515913354/flow-logs-example.txt
Database exists
Table exists
Querying for potential SSH attack...
Source IP        Count        Reports (max 1000) SSH/BruteForce   Country         
103.45.21.47     21           26                  12               China           
221.194.47.233   9            1000                922              China           
221.194.47.221   6            1000                908              China           
121.18.238.125   6            1000                910              China           
221.194.47.243   6            1000                878              China           
189.59.8.121     6            219                 177              Brazil          
110.53.183.228   6            716                 570              China           
221.194.47.245   6            1000                883              China           
118.172.229.184  4            6                   6                Thailand        
139.199.227.71   4            43                  23               China           
58.218.205.102   4            287                 215              China           
202.160.160.86   4            8                   5                India           
114.143.101.2    4            24                  17               India           
5.101.40.10      3            266                 194              Netherlands     
113.195.145.80   3            69                  54               China
...
```

`Source IP`      the source of the group of suspicious unauthorized SSH requests

`Count`          the number of flows from the input file that indicate unauthorized SSH requests

`Reports`        the number of times the source IP has been reported to AbuseIPDB in the past 60 days. A value of 1000 likely                   indicated there are greater than 1000 reports in this time period.

`SSH/BruteForce` the number of these reports that were taggged by the reporting party as SSH or Brute Force or both

`Country`        the country from in which the source IP resides


Once all suspicious IPs are identified in the table, a prompt is given to the user with the option to report any of these IPs to AbuseIPDB. Once reported, the public report will appear immediately in AbuseIPDB. Only IPs from the output table are allowed to be reported in the prompt. Example:

```
...
185.165.29.189   2            56                  19               Romania         
222.186.15.40    2            38                  25               China           
58.53.219.75     2            215                 173              China           
103.89.88.106    2            54                  51               Viet Nam        
103.89.88.104    2            61                  51               Viet Nam        
172.196.179.45   2            3                   1                Australia       
103.212.222.138  2            84                  75               Korea, Republic of

 To report one of these IPs, enter report <IP>. Type quit to exit.

>report asdf
Invalid IP passed.
>report 58.53.219.750
Invalid IP passed.
>report 58.53.219.75
Valid input, reporting IP to AbuseIPDB...
{
    "ip": "58.53.219.75", 
    "success": true
}
>quit
```

## Additional References

[AWS Python SDK (boto3)](https://boto3.readthedocs.io/en/latest/index.html)

[AWS S3](https://aws.amazon.com/s3/)

[AWS Athena](https://aws.amazon.com/athena/)

[AbuseIPDB](https://www.abuseipdb.com/)
