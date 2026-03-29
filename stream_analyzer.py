import csv
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta

#Config 
BRUTE_FORCE_THRESHOLD      = 5
CRED_STUFF_THRESHOLD_USERS = 5
BOT_REQUEST_THRESHOLD      = 20
TIME_WINDOW                = timedelta(seconds=60)
ALERT_TTL                  = timedelta(minutes=10)
LOG_FILE                   = 'logs.csv'
REQUIRED_COLUMNS           = {'timestamp', 'ip', 'user', 'user_agent', 'endpoint', 'success'}

#State
brute_force_window = defaultdict(deque)  # (ip, user)     -> deque[timestamp]
cred_stuff_window  = defaultdict(deque)  # ip             -> deque[(timestamp, user)]
bot_window         = defaultdict(deque)  # (ip, endpoint) -> deque[timestamp]
alerted            = {}                  # (kind, key)    -> timestamp последнего алерта

#Helpers
def evict(dq, now):
    while dq and (now - dq[0]) > TIME_WINDOW:
        dq.popleft()

def evict_tuples(dq, now):
    while dq and (now - dq[0][0]) > TIME_WINDOW:
        dq.popleft()

def alert(kind, key, detail, now):
    alert_key = (kind, key)
    last = alerted.get(alert_key)
    if last is None or (now - last) > ALERT_TTL:
        alerted[alert_key] = now
        print(f"[ALERT] {kind} | {detail}")

#Detectors
def check_brute_force(ip, user, ts):
    key = (ip, user)
    dq = brute_force_window[key]
    evict(dq, ts)
    dq.append(ts)
    if len(dq) > BRUTE_FORCE_THRESHOLD:
        alert("Brute Force", key,
              f"ip={ip} user={user} | {len(dq)} attempts in 60s", ts)

def check_credential_stuffing(ip, user, ts):
    dq = cred_stuff_window[ip]
    evict_tuples(dq, ts)
    dq.append((ts, user))
    unique = len(set(u for _, u in dq))
    if unique > CRED_STUFF_THRESHOLD_USERS:
        alert("Credential Stuffing", ip,
              f"ip={ip} | {unique} unique users in 60s", ts)

def check_bot(ip, endpoint, ts):
    key = (ip, endpoint)
    dq = bot_window[key]
    evict(dq, ts)
    dq.append(ts)
    if len(dq) > BOT_REQUEST_THRESHOLD:
        alert("Bot Activity", key,
              f"ip={ip} endpoint={endpoint} | {len(dq)} requests in 60s", ts)

#Stream
def stream_logs(path):
    try:
        f = open(path, newline='')
    except FileNotFoundError:
        sys.exit(f"[ERROR] File not found: {path}")

    reader = csv.DictReader(f)

    missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
    if missing:
        sys.exit(f"[ERROR] Missing columns: {missing}")

    processed = 0
    skipped   = 0

    for row in reader:
        try:
            ts = datetime.fromisoformat(row['timestamp'])
        except ValueError:
            skipped += 1
            continue

        ip       = row['ip']
        user     = row['user']
        endpoint = row['endpoint']
        success  = int(row['success'])

        if success == 0:
            check_brute_force(ip, user, ts)
            check_credential_stuffing(ip, user, ts)

        check_bot(ip, endpoint, ts)
        processed += 1

    f.close()
    print(f"\n[INFO] Processed {processed} rows | Skipped {skipped} bad rows")
    total_alerts = sum(1 for _ in alerted)
    print(f"[INFO] Total unique alerts fired: {total_alerts}")

#Main
if __name__ == '__main__':
    stream_logs(LOG_FILE)