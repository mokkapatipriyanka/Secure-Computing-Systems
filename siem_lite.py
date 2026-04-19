import re
import json
import sys
from collections import Counter

def parse_log_file(log_file_path):
    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            log_data = f.read()
    except FileNotFoundError:
        print(f"[ERROR] Log file '{log_file_path}' not found!")
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied to read '{log_file_path}'")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to read log file: {e}")
        sys.exit(1)
    
    pattern = r'Failed password.*from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    failed_ips = re.findall(pattern, log_data)
    
    return failed_ips

def analyze_threats(failed_ips, threshold):
    ip_counts = Counter(failed_ips)
    malicious_ips = {ip: count for ip, count in ip_counts.items() if count >= threshold}
    
    return malicious_ips, ip_counts

def export_to_json(malicious_ips, output_file):
    report = {
        "threat_report": {
            "total_threats_detected": len(malicious_ips),
            "malicious_ips": [
                {
                    "ip_address": ip,
                    "failed_attempts": count,
                    "threat_level": "HIGH" if count >= 5 else "MEDIUM"
                }
                for ip, count in sorted(malicious_ips.items(), key=lambda x: x[1], reverse=True)
            ]
        }
    }
    
    try:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"[SUCCESS] Threat report exported to '{output_file}'")
    except Exception as e:
        print(f"[ERROR] Failed to export JSON: {e}")

def main():
    print("=" * 70)
    print("SIEM LITE - Security Information and Event Management")
    print("=" * 70)
    
    if len(sys.argv) < 3:
        print("\n[USAGE]")
        print(f"  python {sys.argv[0]} <log_file> <threshold>")
        print("\n[EXAMPLE]")
        print(f"  python {sys.argv[0]} auth.log 3")
        print("\n[PARAMETERS]")
        print("  log_file  : Path to authentication log file")
        print("  threshold : Number of failed attempts to trigger alert (e.g., 3)")
        sys.exit(1)
    
    log_file = sys.argv[1]
    
    try:
        threshold = int(sys.argv[2])
        if threshold < 1:
            raise ValueError("Threshold must be positive")
    except ValueError as e:
        print(f"[ERROR] Invalid threshold: {sys.argv[2]}")
        print(f"[ERROR] {e}")
        print("[INFO] Threshold must be a positive integer (e.g., 3, 5, 10)")
        sys.exit(1)
    
    print(f"\n[CONFIG]")
    print(f"  Log file: {log_file}")
    print(f"  Alert threshold: {threshold} failed attempts")
    print()
    
    print("[STEP 1] Parsing log file...")
    failed_ips = parse_log_file(log_file)
    print(f"[INFO] Found {len(failed_ips)} failed login attempts")
    
    print("\n[STEP 2] Analyzing threats...")
    malicious_ips, all_ip_counts = analyze_threats(failed_ips, threshold)
    
    print("\n" + "=" * 70)
    print("THREAT ANALYSIS RESULTS")
    print("=" * 70)
    
    print(f"\n[ALL FAILED LOGIN ATTEMPTS]")
    for ip, count in sorted(all_ip_counts.items(), key=lambda x: x[1], reverse=True):
        status = "ALERT" if count >= threshold else "Below threshold"
        print(f"  {ip:<15} - {count:>3} attempts {status}")
    
    print(f"\n[MALICIOUS IPS DETECTED] (>= {threshold} attempts)")
    if malicious_ips:
        for ip, count in sorted(malicious_ips.items(), key=lambda x: x[1], reverse=True):
            threat_level = "HIGH" if count >= 5 else "MEDIUM"
            print(f"  {ip:<15} - {count:>3} attempts [{threat_level}]")
    else:
        print("  No threats detected above threshold.")
    
    print("\n[STEP 3] Exporting threat report...")
    output_file = "threat_report.json"
    export_to_json(malicious_ips, output_file)
    
    print("\n[COMPLETE] SIEM analysis finished.")
    print("=" * 70)

if __name__ == "__main__":
    main()