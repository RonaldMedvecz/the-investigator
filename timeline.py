from datetime import datetime

# Step 1: Read events from both log files
with open("evidence/auth_events.log", "r") as auth_file:
    auth_events = auth_file.readlines()

with open("evidence/file_events.log", "r") as file_file:
    file_events = file_file.readlines()

# Step 2: Merge all events into one list
all_events = auth_events + file_events

# Step 3: Sort events in chronological order by date and time
def event_timestamp(line):
    return datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")

all_events.sort(key=event_timestamp)

# Step 4: Print the merged timeline, flagging key events
print("=== Incident Timeline ===")
for line in all_events:
    line = line.rstrip("\n")
    if not line:
        continue
    is_key = (
        "SUCCESS LOGIN" in line
        or ".locked" in line
        or "READ_ME" in line
    )
    if is_key:
        print(f"*** KEY EVENT *** {line}")
    else:
        print(line)
