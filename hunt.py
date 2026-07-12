from collections import Counter, defaultdict
import re

# Step 1: Open and read the network traffic log
with open("evidence/network_traffic.log", "r") as log_file:
    lines = log_file.readlines()

# Step 2: Parse each line into timestamp, source IP, and destination IP:port
line_pattern = re.compile(
    r"(\d{2}:\d{2}:\d{2})\s+(\d+\.\d+\.\d+\.\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+:\d+)"
)
pair_timestamps = defaultdict(list)
for line in lines:
    match = line_pattern.search(line)
    if match:
        timestamp, source_ip, dest = match.groups()
        pair = (source_ip, dest)
        pair_timestamps[pair].append(timestamp)

# Step 3: Count how many times each (source -> destination:port) pair appears
pair_counts = Counter({pair: len(times) for pair, times in pair_timestamps.items()})

# Step 4: Find the pair with the most connections
top_pair, top_count = pair_counts.most_common(1)[0]
source_ip, dest = top_pair

# Step 5: Print the beaconing suspect and its connection timestamps
print("=== Beaconing Suspect ===")
print(f"{source_ip} -> {dest}")
print(f"Connections: {top_count}")
print("Timestamps:")
for ts in pair_timestamps[top_pair]:
    print(f"  {ts}")
