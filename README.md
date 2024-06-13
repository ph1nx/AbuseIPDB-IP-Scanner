# AbuseIPDB IP Scanner

This Python script utilizes the AbuseIPDB API to check the malicious activity of IP addresses listed in a CSV file. It retrieves information such as ISP, country, number of abuse reports, and abuse confidence score for each IP address within the last 90 days.

### Requirements

- Python 3.x
- `requests` library
- Install the required Python package using pip:

```bash
pip install requests
```

### Description

1. **API Key Setup**: 
   - Requires a valid VirusTotal API key (`apikey`) to authenticate requests.

2. **Function `check_ip`**: 
   - Sends a GET request to AbuseIPDB for each IP address in the list.
   - Retrieves and parses the JSON response to extract details such as 'Country', 'ISP', 'Total No of Reports', 'Distinct Users', 'Usage Type', 'Domain', and 'Abuse Confidence Score'.

3. **CSV Handling**: 
   - Reads a CSV file (`IP_list.csv`) containing a list of IP addresses.
   - Writes the scan results to another CSV file (`IP_score.csv`) with columns for 'IP Address', 'Country', 'ISP', 'Total No of Reports', 'Distinct Users', 'Usage Type', 'Domain', and 'Abuse Confidence Score'.

4. Performs API requests with error handling for API rate limits, and JSON parsing errors.

### Usage

1. Replace `apikey` with your own AbuseIPDB API key.
2. Prepare a CSV file (`IP_list.csv`) with a header row and IP addresses listed under the 'IP Address' column.
3. Adjust file paths (`input_file`, `output_file`) as per your local directory structure.
4. Run the script to initiate the scanning process.

```bash
python AbuseIPDB_ip_scan.py
```
5. Monitor the console for progress updates and any encountered errors.

---

For detailed information and updates, refer to the [AbuseIPDB API Documentation](https://docs.abuseipdb.com/).

