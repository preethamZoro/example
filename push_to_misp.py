import requests
import json
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings (only for testing)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

MISP_URL = "https://192.168.1.114"
API_KEY = "YOUR_API_KEY_HERE"  # Replace with actual key
LOG_FILE = "/opt/cowrie/var/log/cowrie.json"

headers = {
    "Authorization": API_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json"
}

def create_misp_event():
    """Create a new event in MISP"""
    event_data = {
        "Event": {
            "info": "Automated Cowrie SSH attack report",
            "distribution": "0",
            "threat_level_id": "3",
            "analysis": "2"
        }
    }
    
    try:
        response = requests.post(
            f"{MISP_URL}/events",
            headers=headers,
            json=event_data,
            verify=False,
            timeout=10
        )
        response.raise_for_status()
        return response.json()["Event"]["id"]
        
    except requests.exceptions.RequestException as e:
        print(f"[!] Event creation failed: {str(e)}")
        if hasattr(e, 'response') and e.response:
            print(f"HTTP {e.response.status_code}: {e.response.text}")
        return None

def add_ip_attribute(event_id, ip):
    """Add IP attribute to existing event"""
    attr_data = {
        "Attribute": {
            "type": "ip-src",
            "category": "Network activity",
            "to_ids": True,
            "value": ip,
            "comment": "Automated from Cowrie honeypot"
        }
    }
    
    try:
        response = requests.post(
            f"{MISP_URL}/attributes/add/{event_id}",
            headers=headers,
            json=attr_data,
            verify=False,
            timeout=5
        )
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"  [!] Failed to add {ip}: {str(e)}")
        return False

def main():
    # Step 1: Create MISP event
    event_id = create_misp_event()
    if not event_id:
        exit(1)
        
    print(f"[+] Created MISP event ID: {event_id}")

    # Step 2: Process Cowrie logs
    seen_ips = set()
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                try:
                    log = json.loads(line.strip())
                    if log.get("eventid") == "cowrie.login.failed" and "src_ip" in log:
                        seen_ips.add(log["src_ip"])
                except json.JSONDecodeError:
                    continue
                    
    except IOError as e:
        print(f"[!] Log file error: {str(e)}")
        exit(1)

    # Step 3: Add IP attributes
    print(f"[*] Found {len(seen_ips)} attacker IPs")
    for ip in seen_ips:
        if add_ip_attribute(event_id, ip):
            print(f"  [+] Added: {ip}")

if __name__ == "__main__":
    main()
