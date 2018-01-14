# Final Project for 561 Fall 2017:  Identifying and Reporting Potential SSH Attackers from IP Flow Logs (irpSSHa)

## Methodology

Given a file containing IP flow log data in the expected format (see [example](flow-logs-example.txt)), save remotely in AWS S3 and 
use the data in S3 to run dynamic SQL queries to identify flows that indicate potential SSH attack attempts. 

## Requirements

It is recommended that the destination for the flows be secured enough to reject unauthorized SSH traffic. In particular, ssh login 
with username/password should be disabled and only whitelisted IPs should be allowed. For more information on securing hosts against 
ssh attackers, see ["Recommendations"](https://www.symantec.com/connect/articles/analyzing-malicious-ssh-login-attempts).

The user is required to have an AWS account with S3 and Athena enabled in the same region. AWS credentials should be stored 
locally in ~/.aws/credentials. [More info](https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration).

While the included AbuseIPDB API key is free to use, it is also recommended that any regular user registers for their own account 
to personalize the reports and avoid rate limiting. An account can be [created here](https://www.abuseipdb.com/register).

## Running the script

Run `python attacks_from_data.py -h` for help and info about execution requirements.

### Output



## References

[AWS Python SDK (boto3)](https://boto3.readthedocs.io/en/latest/index.html)
[AWS S3](https://aws.amazon.com/s3/)
[AWS Athena](https://aws.amazon.com/athena/)
[AbuseIPDB](https://www.abuseipdb.com/)