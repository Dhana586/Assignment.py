import csv
from collections import defaultdict

# Configurable failed login attempt threshold
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(log_file_path):
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_logins = defaultdict(int)
    
    with open(log_file_path, 'r') as file:
        for line in file:
            # Extract IP address
            ip = line.split()[0]
            ip_requests[ip] += 1
            
            # Extract endpoint
            try:
                endpoint = line.split('"')[1].split()[1]
                endpoint_requests[endpoint] += 1
            except IndexError:
                continue

            # Detect failed login attempts
            if "401" in line or "Invalid credentials" in line:
                failed_logins[ip] += 1
    
    return ip_requests, endpoint_requests, failed_logins

def save_to_csv(ip_requests, endpoint_requests, failed_logins, output_file):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        
        # Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        
        writer.writerow([])
        
        # Most Accessed Endpoint
        most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1])
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        
        writer.writerow([])
        
        # Suspicious Activity
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in failed_logins.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])

def display_results(ip_requests, endpoint_requests, failed_logins):
    # Requests per IP
    print("IP Address           Request Count")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20}{count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1])
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    # Suspicious Activity
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20}{count}")

def main():
    log_file_path = "sample.log"
    output_file = "log_analysis_results.csv"
    
    ip_requests, endpoint_requests, failed_logins = parse_log_file(log_file_path)
    
    display_results(ip_requests, endpoint_requests, failed_logins)
    save_to_csv(ip_requests, endpoint_requests, failed_logins, output_file)
    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    main()
