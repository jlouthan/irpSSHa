# AbuseIPDB Client:  https://www.abuseipdb.com/api.html
import requests
import json
import abuseIPDB

BASE_URL = "https://www.abuseipdb.com/"
API_KEY = abuseIPDB.API_KEY
DAYS = 60
# List of categories codes:  https://www.abuseipdb.com/categories
BRUTE_FORCE_CAT = 18
SSH_CAT = 22
# Public comment that shows in the AbuseIPDB site with report
REPORT_COMMENT = "SSH brute force attempt"

# Given a source IP address, queries the AbuseIPDB API and returns the number of times the IP
# has been reported in the last 60 days, and the number of those reports that were tagged with 
# the "ssh" or "brute force" categories, or both
def query_db(source_ip):
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

# Given a source IP, reports to AbuseIPDB with the default account and comment. Indicates
# that suspected attack is of type "SSH" and "Brute Force". Prints JSON response.
def report_ip(source_ip):
    payload = {'key': API_KEY, "ip": source_ip, "comment": REPORT_COMMENT, "category": str(BRUTE_FORCE_CAT) + "," + str(SSH_CAT)}
    res = requests.post(BASE_URL + "/report/json", params=payload)
    print(json.dumps(res.json(), indent=4))