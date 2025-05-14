import requests

MISP_URL = "https://192.168.1.114"  # your MISP IP or hostname
API_KEY = "YOUR_API_KEY_HERE"       # paste your real MISP API key
LOG_FILE = "/opt/cowrie/var/log/cowrie.json"

headers = {
    "Authorization": API_KEY,
    "Accept": "application/json",
    "Content-type": "application/json"
}

# Create a new MISP event
event_data = {
    "Event": {
        "info": "Cowrie SSH attack IPs",
        "distribution": "0",       # Your organization only
        "threat_level_id": "3",    # Low
        "analysis": "2"            # Completed
    }
}

response = requests.post(f"{MISP_URL}/events", headers=headers, json=event_data, verify=False)

if response.status_code == 200:
    event = response.json()
    event_id = event["Event"]["id"]
    print(f"[+] Created MISP event ID {event_id}")
else:
    print("[!] Failed to create event")
    exit()

# Extract IPs from Cowrie log
import json
seen_ips = set()
with open(LOG_FILE, "r") as f:
    for line in f:
        try:
            log = json.loads(line.strip())
            if "src_ip" in log:
                seen_ips.add(log["src_ip"])
        except:
            continue

# Push each IP as an attribute
for ip in seen_ips:
    attr_data = {
        "Attribute": {
            "type": "ip-src",
            "category": "Network activity",
            "to_ids": True,
            "value": ip
        }
    }
    r = requests.post(f"{MISP_URL}/attributes/add/{event_id}", headers=headers, json=attr_data, verify=False)
    if r.status_code == 200:
        print(f"  [+] Added IP: {ip}")
    else:
        print(f"  [!] Failed to add IP: {ip}")