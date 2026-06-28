from collections import Counter
import re

# Step 1: Open and read the log file
with open("server_access.log", "r") as log_file:
    lines = log_file.readlines()

# Step 2: Keep only lines that contain a failed login
failed_lines = [line for line in lines if "FAILED LOGIN" in line]

# Step 3: Extract the IP address from each failed login line
ip_pattern = re.compile(r"from (\d+\.\d+\.\d+\.\d+)")
ips = []
for line in failed_lines:
    match = ip_pattern.search(line)
    if match:
        ips.append(match.group(1))

# Step 4: Count how many times each IP appears
ip_counts = Counter(ips)

# Step 5: Print a summary sorted from most to fewest attempts
print("=== Failed Login Summary ===")
for ip, count in ip_counts.most_common():
    print(f"{ip}: {count} failed attempt(s)")
