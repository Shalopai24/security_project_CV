import pandas as pd
import sys

#Config 
BRUTE_FORCE_THRESHOLD      = 5
CRED_STUFF_THRESHOLD_USERS = 5
CRED_STUFF_THRESHOLD_TOTAL = 10
BOT_REQUEST_THRESHOLD      = 20
TIME_WINDOW                = '60s'  
LOG_FILE                   = 'logs.csv'
REQUIRED_COLUMNS           = {'timestamp', 'ip', 'user', 'user_agent', 'endpoint', 'success'}

#Load & validate
def load_logs(path):
    try:
        df = pd.read_csv(path)
    except FileNotFoundError:
        sys.exit(f"[ERROR] File not found: {path}")

    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        sys.exit(f"[ERROR] Missing columns: {missing}")

    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    dropped = df['timestamp'].isna().sum()
    if dropped:
        print(f"[WARN] Dropped {dropped} rows with invalid timestamps")
    df = df.dropna(subset=['timestamp'])

    return df

#Detectors 
def detect_brute_force(df):
    failed = df[df['success'] == 0].copy()
    failed = failed.sort_values('timestamp')
    window = (
        failed.groupby(['ip', 'user'])
        .rolling(TIME_WINDOW, on='timestamp')['success']
        .count()
        .reset_index()
        .rename(columns={'success': 'attempts'})
    )
    alerts = window[window['attempts'] > BRUTE_FORCE_THRESHOLD]
    return alerts.groupby(['ip', 'user']).first().reset_index()

def detect_credential_stuffing(df):
    failed = df[df['success'] == 0].copy()
    failed = failed.set_index('timestamp')
    window = (
        failed.groupby('ip')[['user']]
        .resample('60s') #.rolling doesn't work with 'nunique' - fixed in streaming version
        .agg(unique_users=('user', 'nunique'), total_attempts=('user', 'count'))
        .reset_index()
    )
    return window[
        (window['unique_users'] > CRED_STUFF_THRESHOLD_USERS) &
        (window['total_attempts'] > CRED_STUFF_THRESHOLD_TOTAL)
    ][['ip', 'timestamp', 'unique_users', 'total_attempts']]

def detect_bots(df):
    df = df.sort_values('timestamp')
    window = (
        df.groupby(['ip', 'user_agent', 'endpoint'])
        .rolling(TIME_WINDOW, on='timestamp')['success']
        .count()
        .reset_index()
        .rename(columns={'success': 'requests'})
    )
    alerts = window[window['requests'] > BOT_REQUEST_THRESHOLD]
    return alerts.groupby(['ip', 'user_agent', 'endpoint']).first().reset_index()[
        ['ip', 'user_agent', 'endpoint', 'timestamp', 'requests']
    ]

#Report
def report(label, df):
    print(f"\n{'='*50}")
    print(f"  {label}: {len(df)} alert(s)")
    print('='*50)
    if df.empty:
        print("  No threats detected.")
    else:
        print(df.to_string(index=False))

#Main
if __name__ == '__main__':
    df = load_logs(LOG_FILE)
    print(f"[INFO] Loaded {len(df)} valid log entries")

    report("Brute Force",         detect_brute_force(df))
    report("Credential Stuffing", detect_credential_stuffing(df))
    report("Bot Activity",        detect_bots(df))