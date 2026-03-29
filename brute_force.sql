WITH login_attempts AS (
    SELECT 
        ip,
        user,
        timestamp,
        COUNT(*) OVER (
            PARTITION BY ip, user
            ORDER BY timestamp
            RANGE BETWEEN INTERVAL '60 seconds' PRECEDING AND CURRENT ROW
        ) AS attempts_in_window
    FROM logs
    WHERE success = 0
),
first_alert AS (
    SELECT *,
        ROW_NUMBER() OVER (PARTITION BY ip, user ORDER BY timestamp) AS rn
    FROM login_attempts
    WHERE attempts_in_window > 5
)
SELECT ip, user, timestamp, attempts_in_window
FROM first_alert
WHERE rn = 1  -- только первый момент превышения порога
ORDER BY timestamp;