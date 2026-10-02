import pandas as pd

LOG_FILE = "data/security_logs.csv"


def run_tests():

    logs = pd.read_csv(LOG_FILE)

    print("\n======================================")
    print(" SECURITY SYSTEM TESTING")
    print("======================================")

    # Test 1: Normal Activity
    normal = logs[
        (logs["failed_attempts"] < 5) &
        (logs["request_count"] < 1000) &
        (logs["status"] == "normal")
    ]

    print("\nTest Case 1 - Normal Activity")
    print(f"Records Found: {len(normal)}")
    print("Result: PASS" if len(normal) > 0 else "Result: FAIL")

    # Test 2: Brute Force
    brute_force = logs[
        logs["failed_attempts"] >= 10
    ]

    print("\nTest Case 2 - Brute Force Attack")
    print(f"Records Found: {len(brute_force)}")
    print("Result: PASS" if len(brute_force) > 0 else "Result: FAIL")

    # Test 3: High Traffic
    high_traffic = logs[
        logs["request_count"] >= 1000
    ]

    print("\nTest Case 3 - High Traffic Attack")
    print(f"Records Found: {len(high_traffic)}")
    print("Result: PASS" if len(high_traffic) > 0 else "Result: FAIL")

    # Test 4: Malware
    malware = logs[
        logs["file_name"].str.contains(
            "malware", case=False, na=False
        )
    ]

    print("\nTest Case 4 - Malware Activity")
    print(f"Records Found: {len(malware)}")
    print("Result: PASS" if len(malware) > 0 else "Result: FAIL")

    # Test 5: Suspicious Activity
    suspicious = logs[
        logs["status"] == "suspicious"
    ]

    print("\nTest Case 5 - Suspicious Activity")
    print(f"Records Found: {len(suspicious)}")
    print("Result: PASS" if len(suspicious) > 0 else "Result: FAIL")

    print("\n======================================")
    print(" TESTING COMPLETED")
    print("======================================")


if __name__ == "__main__":
    run_tests()