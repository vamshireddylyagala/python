import re
import csv
import argparse
from collections import Counter

def process_log_file(log_file):
    """
    Process the log file to extract IP requests, endpoint hits, 
    and failed login attempts.
    """
    ip_counter = Counter()
    endpoint_counter = Counter()
    failed_login_attempts = Counter()

    log_pattern = (
        r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s-\s-\s\[\S+\s\S+\]\s"(?P<method>\S+)\s(?P<endpoint>\S+)\s\S+"\s(?P<status_code>\d+)\s\d+'
    )
    failed_login_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+).*"Invalid credentials"'

    with open(log_file, 'r') as file:
        for line in file:
            log_match = re.match(log_pattern, line)
            if log_match:
                ip = log_match.group('ip')
                endpoint = log_match.group('endpoint')
                status_code = log_match.group('status_code')

                ip_counter[ip] += 1
                endpoint_counter[endpoint] += 1

                if status_code == "401" or re.search(failed_login_pattern, line):
                    failed_login_attempts[ip] += 1

    return ip_counter, endpoint_counter, failed_login_attempts

def get_most_accessed_endpoint(endpoint_counter):
    """
    Identify the most accessed endpoint from the counter.
    """
    return endpoint_counter.most_common(1)[0] if endpoint_counter else (None, 0)

def detect_suspicious_activity(failed_logins, threshold=10):
    """
    Detect suspicious activity based on failed login attempts exceeding a threshold.
    """
    return {ip: count for ip, count in failed_logins.items() if count > threshold}

def save_results_to_csv(ip_counter, most_accessed_endpoint, suspicious_ips):
    """
    Save the analysis results to a CSV file.
    """
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counter.items():
            writer.writerow([ip, count])

        endpoint_name, endpoint_count = most_accessed_endpoint
        writer.writerow(['Most Accessed Endpoint', endpoint_name if endpoint_name else 'N/A'])
        writer.writerow(['Access Count', endpoint_count])

        writer.writerow(['Suspicious Activity Detected', 'Failed Login Attempts'])
        if suspicious_ips:
            for ip, count in suspicious_ips.items():
                writer.writerow([ip, count])
        else:
            writer.writerow(['None', 0])

def display_results(ip_counter, most_accessed_endpoint, suspicious_ips):
    """
    Display the analysis results in the console.
    """
    print("IP Address           Request Count")
    for ip, count in ip_counter.most_common():
        print(f"{ip:<20}{count}")

    endpoint_name, endpoint_count = most_accessed_endpoint
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{endpoint_name} (Accessed {endpoint_count} times)")

    if suspicious_ips:
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count}")
    else:
        print("\nNo suspicious activity detected.")

def main():
    """
    Main function to parse arguments, process the log file,
    and display/save results.
    """
    parser = argparse.ArgumentParser(
        description="Analyze log file for IP requests, endpoints, and suspicious activity."
    )
    parser.add_argument('log_file', type=str, help="Path to the log file.")
    parser.add_argument('--threshold', type=int, default=10, help="Threshold for suspicious activity detection.")
    args = parser.parse_args()

    ip_counter, endpoint_counter, failed_logins = process_log_file(args.log_file)

    most_accessed_endpoint = get_most_accessed_endpoint(endpoint_counter)
    suspicious_ips = detect_suspicious_activity(failed_logins, args.threshold)

    display_results(ip_counter, most_accessed_endpoint, suspicious_ips)
    save_results_to_csv(ip_counter, most_accessed_endpoint, suspicious_ips)

if __name__ == '__main__':
    main()
