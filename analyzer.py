import pandas as pd

#Reading logs
df = pd.read_csv("logs.csv")

#Converting Timestamp
df['timestamp'] = pd.to_datetime(df['timestamp'])

#We need only failed logins(in case if it's a WiFi with multiple users)
df = df[df['success'] == 0]

#Some Settings
BRUTE_FORCE_THRESHOLD = 5       
CRED_STUFF_THRESHOLD_USERS = 5  
CRED_STUFF_THRESHOLD_TOTAL = 10
TIME_WINDOW = '1T' #Explanation: 5 attempts in 1 month is not a brute force      

#Index
df = df.set_index('timestamp')
#Attempts per user in a timestamp (brute force detection)
bf_window = df.groupby(['ip','user']).resample(TIME_WINDOW).size().reset_index(name='attempts')
brute_force = bf_window[bf_window['attempts'] > BRUTE_FORCE_THRESHOLD]

print("Brute Force Detected:")
print(brute_force)

#Amount of unique users and attempts per each user (credential stuffing)
cs_window = df.groupby('ip').resample(TIME_WINDOW).agg(
    unique_users=('user', 'nunique'),
    total_attempts=('user', 'count')
).reset_index()
credential_stuffing = cs_window[
    (cs_window['unique_users'] > CRED_STUFF_THRESHOLD_USERS) &
    (cs_window['total_attempts'] > CRED_STUFF_THRESHOLD_TOTAL)
]

print("Credential Stuffing Detected:")
print(credential_stuffing)

#grouping by IP, user-agent, enpoint and looking for suspicious activities (bot detection)
bot_activity = df.groupby(['ip','user_agent','endpoint']).resample(TIME_WINDOW).size().reset_index(name='requests')
BOT_REQUEST_THRESHOLD = 20
bot_suspect = bot_activity[bot_activity['requests'] > BOT_REQUEST_THRESHOLD]

print("Possible Bot Activity Detected:")
print(bot_suspect)