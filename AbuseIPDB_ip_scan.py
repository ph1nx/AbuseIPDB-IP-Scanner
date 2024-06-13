import csv
import requests

# //////////////////////////////////////////////
#
# Python script for AbuseIPDB API v2 list of IP address analysis
# by ph1nx
#
# Performs bulk IP address analysis
#
# Reports for each IP entry is saved to a CSV file
#
# //////////////////////////////////////////////

global apikey

apikey = 'YOUR_AbuseIPDB_API_KEY' # Replace with your AbuseIPDB API Key

# Function to check if an IP address is malicious
def check_ip(ip_address):
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90,
        'verbose': '',
    }
    headers = {
        'Key': apikey,
        'Accept': 'application/json'
    }
    
    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()  # Raise error for non-200 status codes

        response_json = response.json()
        if 'data' not in response_json:
            raise ValueError("Invalid response structure")

        attributes = response_json['data']
        
        isp = attributes.get('isp')
        country = attributes.get('countryName')
        totalReports = attributes.get('totalReports')
        numDistinctUsers = attributes.get('numDistinctUsers')
        usageType = attributes.get('usageType')
        domain = attributes.get('domain')
        abuseConfidenceScore = attributes.get('abuseConfidenceScore')

        return {
            'IP Address': ip_address,
            'Country': country,
            'ISP': isp,
            'Total No of Reports': totalReports,
            'Distinct Users': numDistinctUsers,
            'Usage Type': usageType,
            'Domain': domain,
            'Abuse Confidence Score': abuseConfidenceScore,
        }
    
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while checking IP {ip_address}: {e}")
        print("API rate limit per day might be completed.")
        return None
    
    except ValueError as e:
        print(f"Error parsing JSON response for IP {ip_address}: {e}")
        return None
    
    except Exception as e:
        print(f"An unexpected error occurred while processing IP {ip_address}: {e}")
        return None


# Read the CSV file
input_file = '//home//kali//Desktop//IP_list.csv'  # Input CSV file path
output_file = '//home//kali//Desktop//IP_score.csv'  # Output CSV file path

try:
    with open(input_file, 'r', encoding='utf-8-sig') as infile, open(output_file, 'w', newline='', encoding='utf-8') as outfile:
        reader = csv.DictReader(infile)
        ip_list = list(reader)
        
        if len(ip_list) > 1000:
            print("IP count exceeding AbuseIPDB rate limit. Checking malicious score for the first 1000 IPs.")
            ip_list = ip_list[:1000]

        fieldnames = ['IP Address', 'Country', 'ISP', 'Total No of Reports', 'Distinct Users', 'Usage Type', 'Domain', 'Abuse Confidence Score']
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)

        writer.writeheader()
        print("Started AbuseIPDB IP Scan...")
        for row in ip_list:
            try:
                column_name = 'IP Address'  # Column name containing IP Addresses
                ip_address = row[column_name]  # Corrected to fetch IP address from the row
                data = check_ip(ip_address)
                if data:
                    writer.writerow(data)
            
            except KeyError:
                print(f"The CSV does not contain the expected column '{column_name}'.")
                break
            
            except Exception as e:
                print(f"An error occurred while processing IP {ip_address}: {e}")
                break

    print("IPs scan completed!!")

except FileNotFoundError:
    print("The specified file was not found.")

except Exception as e:
    print(f"An unexpected error occurred: {e}")
