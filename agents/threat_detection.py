import pandas as pd
import joblib

LOG_FILE = "data/security_logs.csv"
MODEL_FILE = "models/isolation_forest_model.pkl"


def detect_threats():

    logs = pd.read_csv(LOG_FILE)

    # Load trained ML model
    model = joblib.load(MODEL_FILE)

    # ML features
    features = logs[
        ["failed_attempts", "request_count"]
    ]

    # ML prediction
    logs["ML_Prediction"] = model.predict(features)

    logs["ML_Result"] = logs["ML_Prediction"].apply(
        lambda x: "Anomaly" if x == -1 else "Normal"
    )

    print("\n===== THREAT DETECTION AGENT =====")

    for _, log in logs.iterrows():

        failed_attempts = log["failed_attempts"]
        request_count = log["request_count"]
        file_name = str(log["file_name"]).lower()
        event_type = log["event_type"]

        ml_result = log["ML_Result"]

        # Rule-based threat identification
        if failed_attempts >= 10:
            threat = "Brute Force Attack"

        elif request_count >= 1000:
            threat = "DDoS / High Traffic Attack"

        elif "malware" in file_name:
            threat = "Malware Activity"

        elif event_type == "login" and failed_attempts >= 5:
            threat = "Possible Brute Force Attack"

        elif ml_result == "Anomaly":
            threat = "ML Detected Anomaly"

        else:
            threat = "Normal Activity"

        print(
            f"IP: {log['source_ip']} | "
            f"ML: {ml_result} | "
            f"Threat: {threat}"
        )


if __name__ == "__main__":
    detect_threats()