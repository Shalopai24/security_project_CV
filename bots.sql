WITH frequency_analysis AS (
    SELECT 
        ip,
        endpoint,
        user_agent,
        timestamp,
        COUNT(*) OVER (
            PARTITION BY ip, endpoint 
            ORDER BY timestamp 
            ROWS BETWEEN 20 PRECEDING AND CURRENT ROW
        ) AS requests_in_window,
        LAG(timestamp, 20) OVER (
            PARTITION BY ip, endpoint 
            ORDER BY timestamp
        ) AS timestamp_20_req_ago
    FROM logs
)
SELECT 
    ip,
    endpoint,
    user_agent,
    timestamp,
    requests_in_window,
    EXTRACT(EPOCH FROM (timestamp - timestamp_20_req_ago)) AS time_diff_seconds
FROM frequency_analysis
WHERE 
    requests_in_window >= 20
    AND EXTRACT(EPOCH FROM (timestamp - timestamp_20_req_ago)) < 10
    AND timestamp_20_req_ago IS NOT NULL  
ORDER BY time_diff_seconds ASC, timestamp DESC;