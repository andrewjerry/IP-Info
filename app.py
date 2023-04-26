import csv
import ipaddress
import os
import urllib.request
import ipwhois
import time
from datetime import datetime, timedelta

from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

CSV_URL = "https://mask-api.icloud.com/egress-ip-ranges.csv"
CSV_FILE = "egress-ip-ranges.csv"
CIDR_RANGES = set()
LAST_UPDATED = None


def sanitize_csv():
    """
    Retrieve the CIDR ranges from the CSV file and sanitize them.
    """
    cidr_ranges = set()
    with open(CSV_FILE, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            cidr_ranges.add(row[0].strip())
    # Remove the header row
    # cidr_ranges.pop(0)

    # Sanitize the CIDR ranges
    sanitized_cidr_ranges = set()
    for cidr_range in cidr_ranges:
        sanitized_cidr_ranges.add(cidr_range.strip())

    return sanitized_cidr_ranges


def retrieve_csv_file():
    """
    Retrieve the CSV file from the URL if it hasn't been downloaded in the last 24 hours,
    or if it doesn't exist locally.
    """
    global CIDR_RANGES, LAST_UPDATED

    if os.path.exists(CSV_FILE):
        modified_time = os.path.getmtime(CSV_FILE)
        file_age = datetime.now() - datetime.fromtimestamp(modified_time)
        # If the file was modified less than 24 hours ago, load the existing file
        if file_age < timedelta(hours=24):
            if not CIDR_RANGES:
                CIDR_RANGES = sanitize_csv()
            return

    # Download the CSV file from the URL
    urllib.request.urlretrieve(CSV_URL, CSV_FILE)

    CIDR_RANGES = sanitize_csv()
    LAST_UPDATED = datetime.now()


def is_ip_in_cidr(ip: str, cidr_ranges: set) -> bool:
    """
    Check if an IP address is within any of the CIDR ranges.
    """
    ip_obj = ipaddress.ip_address(ip)
    for cidr_range in cidr_ranges:
        try:
            network = ipaddress.ip_network(cidr_range)
            if ip_obj in network:
                return True
        except ValueError:
            pass
    return False

def get_ip_details(ip):
    """
    Looks up the details for a given IP address using the ipwhois library.

    Returns a dictionary containing the organization and location information.
    """
    details = {}

    # Perform the IP lookup using the ipwhois library
    ip_lookup = ipwhois.IPWhois(ip)
    lookup_results = ip_lookup.lookup_rdap()
    # print(lookup_results)

    # Extract the relevant information from the lookup results
    if "entities" in lookup_results:
        details["organization"] = ", ".join(lookup_results["entities"])
    if "asn_description" in lookup_results:
        details["asn_description"] = lookup_results["asn_description"]
    if "asn_country_code" in lookup_results:
        details["asn_country_code"] = lookup_results["asn_country_code"]
    if "city" in lookup_results:
        details["city"] = lookup_results["city"]
    if "region" in lookup_results:
        details["region"] = lookup_results["region"]
    if "country" in lookup_results:
        details["country"] = lookup_results["country"]

    return details


@app.route("/")
def index():
    start_time = time.time()
    ip = request.args.get("ip", "").strip()
    if not ip:
        return render_template("index.html")
    # if not ipaddress.ip_address(ip):
    #     return render_template("index.html", error="Please enter a valid IP address.")

    try:
        ip_address = ipaddress.ip_address(ip)
    except ValueError:
        return render_template("index.html", error="Please enter a valid IP address.")

    ip_info = get_ip_details(ip)
    
    retrieve_csv_file()
    
    response = {
        "ip": ip,
        "is_apple_private_relay": is_ip_in_cidr(ip, CIDR_RANGES),
        "organization": ip_info.get("organization", "Unknown"),
        "city": ip_info.get("city", "Unknown"),
        "country": ip_info.get("country", "Unknown")
    }
    end_time = time.time()
    print("Response time: ", end_time - start_time)

    return render_template("result.html", response=response)





@app.route("/api", methods=["GET"])
def api():
    
    ip = request.args.get("ip")
    if not ip:
        return jsonify(error="Please provide an IP address.")
    if not ipaddress.ip_address(ip):
        return jsonify(error="Please provide a valid IP address.")
    retrieve_csv_file()
    result = is_ip_in_cidr(ip, CIDR_RANGES)
    return jsonify(ip=ip, result=result)


if __name__ == "__main__":
    retrieve_csv_file()
    app.run(debug=True, port=80)
