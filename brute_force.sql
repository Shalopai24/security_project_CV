WITH login_attempts AS (
    SELECT 
        ip, 
        user, 
        timestamp,
        -- timestamp of the user and ip
        LAG(timestamp) OVER (PARTITION BY ip, user ORDER BY timestamp) as prev_timestamp
    FROM logs
    WHERE success = 0 -- only unsuccessful attempts
)
SELECT 
    ip, 
    user, 
    timestamp,
    -- counting time between previous and current attempt
    EXTRACT(EPOCH FROM (timestamp - prev_timestamp)) as seconds_diff
FROM login_attempts
-- if difference is < 2 sec it is definitely a bot
WHERE EXTRACT(EPOCH FROM (timestamp - prev_timestamp)) < 2;
