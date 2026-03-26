-- search of ip's who logged in as 5 or more users
SELECT 
    ip, 
    COUNT(DISTINCT user) AS unique_users_count,
    COUNT(*) AS total_failed_attempts,
    MIN(timestamp) AS attack_start,
    MAX(timestamp) AS attack_end
FROM logs
WHERE success = 0  --only unsuccessful attempts
GROUP BY ip
HAVING COUNT(DISTINCT user) > 5  -- more than five users from one IP == credentials scraping
ORDER BY unique_users_count DESC;
