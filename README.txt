Security Log Analytics Engine (Python & SQL)

A professional detection engine designed to identify automated cyber attacks within authentication and API traffic logs. 
Overview
This project simulates a **Detection Engineering** workflow used in high-traffic platforms like TikTok. It identifies three critical attack patterns by analyzing time-series data and behavioral anomalies.

Key Features:
*   **Brute Force Detection:** Identifies repeated failed login attempts against a single account within a 1-minute sliding window.
*   **Credential Stuffing Detection:** Flags IP addresses attempting to log into multiple unique accounts (indicative of leaked database testing).
*   **Bot Activity Identification:** Detects high-frequency request patterns to specific API endpoints using User-Agent and IP clustering.

Tech Stack
*   Python: Pandas (Time-series resampling, aggregation), NumPy.
*   SQL: Window Functions (`LAG`, `LEAD`), Common Table Expressions (CTEs).
*   Concepts: Time-window analysis, Rate-limiting logic, Anomaly detection.

Detection Logic

| Attack Type       | Logic                           | Threshold (Adjustable) |
| **Brute Force**   | Count failed logins per IP/User | > 5 attempts / min |
| **Cred-Stuffing** | Count unique User IDs per IP    | > 5 users / IP |
| **Bot Traffic**   | Request frequency per Endpoint  | > 20 req / min |

Project Structure
* analyzer.py: Main Python engine using Pandas.
* bots.sql, brute_force.sql, credentials_scraping.sql: Scalable SQL implementation for Big Data environments.
* logs.csv: Sample dataset for testing.
