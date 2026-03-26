WITH frequency_analysis AS (
    SELECT 
        ip,
        endpoint,
        user_agent,
        timestamp,
        -- counting number of requests from 20 previous rows foer this ip
        COUNT(*) OVER (
            PARTITION BY ip, endpoint 
            ORDER BY timestamp 
            ROWS BETWEEN 20 PRECEDING AND CURRENT ROW
        ) as requests_in_window,
        -- timestamp of the 20th request
        LAG(timestamp, 20) OVER (PARTITION BY ip, endpoint ORDER BY timestamp) as timestamp_20_req_ago
    FROM logs
)
SELECT 
    ip, 
    endpoint, 
    user_agent,
    timestamp,
    -- difference in time between 1st and 20th request
    EXTRACT(EPOCH FROM (timestamp - timestamp_20_req_ago)) as time_diff_seconds
FROM frequency_analysis
WHERE 
    requests_in_window >= 20 
    AND EXTRACT(EPOCH FROM (timestamp - timestamp_20_req_ago)) < 10 -- 20 requests in under 10 seconds == bot
ORDER BY timestamp DESC;
