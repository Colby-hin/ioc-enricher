import csv
import ipaddress
import os
import requests
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("VT_API_KEY")

print("API key loaded:", bool(api_key))


with open("ips.txt", "r") as file:
    ip_addresses = [line.strip() for line in file if line.strip()]

print("IPs loaded:", len(ip_addresses))

results = []

for ip_address in ip_addresses:
    print("\nInvestigating:", ip_address)


    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        print("Invalid IP address.")
        raise SystemExit


    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code != 200:
        print("VirusTotal request failed:", response.status_code)
        raise SystemExit
    print("Status code:", response.status_code)


    data = response.json()

    stats = data["data"]["attributes"]["last_analysis_stats"]

    print("Malicious:", stats["malicious"])
    print("Suspicious:", stats["suspicious"])
    print("Harmless:", stats["harmless"])
    print("Undetected:", stats["undetected"])


    attributes = data["data"]["attributes"]

    print("Owner:", attributes.get("as_owner", "Unknown"))
    print("Country:", attributes.get("country", "Unknown"))
    print("Reputation:", attributes.get("reputation", "Unknown"))

    needs_review = stats["malicious"] > 0 or stats["suspicious"] > 0

    results.append({
    "ip": ip_address,
    "malicious": stats["malicious"],
    "suspicious": stats["suspicious"],
    "owner": attributes.get("as_owner", "Unknown"),
    "country": attributes.get("country", "Unknown"),
    "reputation": attributes.get("reputation", "Unknown"),
    "needs_review": needs_review,
})

review_results = [result for result in results if result["needs_review"]]
print("IPs needing review:", len(review_results))

with open("results.csv", "w", newline="") as file:
    fieldnames = ["ip", "malicious", "suspicious", "owner", "country", "reputation", "needs_review"]
    writer = csv.DictWriter(file, fieldnames=fieldnames)

    writer.writeheader()
    writer.writerows(results)

    print("\nResults saved to results.csv")