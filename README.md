# Assignment.py
Log Analysis Script
Overview
This Python script processes web server log files to extract and analyze key information, including:

Requests per IP Address: Counts and ranks IP addresses by the number of requests made.
Most Frequently Accessed Endpoint: Identifies the most accessed resource or URL.
Suspicious Activity Detection: Flags IPs with failed login attempts exceeding a threshold.
The results are displayed in the terminal and saved to a CSV file for further analysis.

Features
Count Requests per IP Address: Displays IP addresses and the number of requests in descending order.
Identify Most Accessed Endpoint: Outputs the most accessed endpoint and its count.
Detect Suspicious Activity: Highlights IPs with excessive failed login attempts.
CSV Output: Saves the results in log_analysis_results.csv.
Prerequisites
Python 3.6 or higher
sample.log file in the same directory as the script
How to Use
Clone or Download the script:

bash
Copy code
git clone https://github.com/your-repo/log-analysis.git
cd log-analysis
Ensure Python is Installed: Verify by running:

bash
Copy code
python --version
If not installed, download it from python.org.

Place the Log File: Ensure the sample.log file is in the same directory as the script.

Run the Script: Execute the script in your terminal:

bash
Copy code
python log_analysis.py
View Results:

Terminal output displays the analysis.
Results are saved in log_analysis_results.csv.
Sample Log File
The script is designed to process log files in the following format:

bash
Copy code
192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
For testing, use the provided sample.log.

Example Output
Terminal
bash
Copy code
IP Address           Request Count
192.168.1.1          15
203.0.113.5          12

Most Frequently Accessed Endpoint:
/home (Accessed 403 times)

Suspicious Activity Detected:
IP Address           Failed Login Attempts
203.0.113.5          12
CSV File
The log_analysis_results.csv contains:

Requests per IP
Most Accessed Endpoint
Suspicious Activity
Configuration
You can adjust the failed login attempt threshold by modifying the FAILED_ATTEMPTS_THRESHOLD variable in the script.
