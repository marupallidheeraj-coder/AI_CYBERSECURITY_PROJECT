import pandas as pd
import joblib
import os

LOG_FILE = "data/security_logs.csv"
MODEL_FILE = "models/isolation_forest_model.pkl"
REPORT_FILE = "reports/security_report.csv"


def generate_report():

    logs = pd.read_csv(LOG_FILE)

    # Load trained ML model
    model = joblib.load(MODEL_FILE)

    # ML prediction
    features = logs[
        ["failed_attempts", "request_count"]
    ]

    logs["ML_Prediction"] = model.predict(features)

    logs["ML_Result"] = logs["ML_Prediction"].apply(
        lambda x: "Anomaly" if x == -1 else "Normal"
    )

    suspicious_logs = logs[
        logs["status"] == "suspicious"
    ].copy()

    report_data = []

    for _, log in suspicious_logs.iterrows():

        ip = log["source_ip"]
        failed_attempts = log["failed_attempts"]
        request_count = log["request_count"]
        file_name = str(log["file_name"]).lower()
        event_type = log["event_type"]

        # Threat identification
        if failed_attempts >= 10:
            threat = "Brute Force Attack"
            action = "Block IP"

        elif request_count >= 1000:
            threat = "DDoS / High Traffic Attack"
            action = "Block IP"

        elif "malware" in file_name:
            threat = "Malware Activity"
            action = "Isolate System"

        elif event_type == "login" and failed_attempts >= 5:
            threat = "Possible Brute Force Attack"
            action = "Temporarily Block IP"

        elif log["ML_Result"] == "Anomaly":
            threat = "ML Detected Anomaly"
            action = "Alert Administrator"

        else:
            threat = "Suspicious Activity"
            action = "Alert Administrator"

        report_data.append({
            "Timestamp": log["timestamp"],
            "Source IP": ip,
            "Event Type": event_type,
            "ML Result": log["ML_Result"],
            "Threat": threat,
            "File": log["file_name"],
            "Response Action": action
        })

    report = pd.DataFrame(report_data)

    # Create reports folder
    os.makedirs("reports", exist_ok=True)

    # Save final report
    report.to_csv(REPORT_FILE, index=False)

    print("\n===== REPORT GENERATION AGENT =====")

    print(f"Total Logs: {len(logs)}")
    print(f"Suspicious Activities: {len(suspicious_logs)}")
    print(f"ML Anomalies: {(logs['ML_Result'] == 'Anomaly').sum()}")

    print(f"Report saved to: {REPORT_FILE}")

    print("\nFinal Security Report:")
    print(report.to_string(index=False))

    print("\nThreat Report Generated Successfully.")


if __name__ == "__main__":
    generate_report()