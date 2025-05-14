import json

log_file = "/opt/cowrie/var/log/cowrie.json"
seen_ips = set()

with open(log_file, "r") as f:
    for line in f:
        try:
            data = json.loads(line.strip())
            if "src_ip" in data:
                seen_ips.add(data["src_ip"])
        except:
            continue

print("Extracted IPs:")
for ip in sorted(seen_ips):
    print(ip)