WITH time_filtered AS (
    SELECT *
    FROM logs
    WHERE 
        success = 0
        AND timestamp >= NOW() - INTERVAL '1 hour'  
),
ip_stats AS (
    SELECT 
        ip,
        COUNT(DISTINCT user)  AS unique_users_count,
        COUNT(*)              AS total_failed_attempts,
        MIN(timestamp)        AS attack_start,
        MAX(timestamp)        AS attack_end,
        EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))) AS duration_seconds
    FROM time_filtered
    GROUP BY ip
    HAVING COUNT(DISTINCT user) > 5
)
SELECT *
FROM ip_stats
ORDER BY unique_users_count DESC;
