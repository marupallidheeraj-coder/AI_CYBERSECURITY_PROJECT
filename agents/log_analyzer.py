import pandas as pd

LOG_FILE = "data/security_logs.csv"


def analyze_logs():
    logs = pd.read_csv(LOG_FILE)

    print("\n===== LOG ANALYZER AGENT =====")
    print(f"Total logs received: {len(logs)}")

    suspicious_logs = logs[logs["status"] == "suspicious"]

    print(f"Suspicious logs found: {len(suspicious_logs)}")

    if len(suspicious_logs) > 0:
        print("\nSuspicious Activities:")
        print(
            suspicious_logs[
                ["timestamp", "source_ip", "event_type", "status"]
            ].to_string(index=False)
        )

    return suspicious_logs


if __name__ == "__main__":
    analyze_logs()