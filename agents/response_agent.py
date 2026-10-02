import pandas as pd
import joblib

LOG_FILE = "data/security_logs.csv"
MODEL_FILE = "models/isolation_forest_model.pkl"


def respond_to_threats():

    logs = pd.read_csv(LOG_FILE)

    # Load ML model
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

    suspicious_logs = logs[
        logs["status"] == "suspicious"
    ].copy()

    print("\n===== RESPONSE AGENT =====")

    for _, log in suspicious_logs.iterrows():

        ip = log["source_ip"]
        failed_attempts = log["failed_attempts"]
        request_count = log["request_count"]
        file_name = str(log["file_name"]).lower()
        ml_result = log["ML_Result"]

        # Response decision
        if "malware" in file_name:
            action = "Isolate System - Malware Detected"

        elif failed_attempts >= 10:
            action = "Block IP - Possible Brute Force"

        elif request_count >= 1000:
            action = "Block IP - High Traffic Detected"

        elif ml_result == "Anomaly":
            action = "Block IP - ML Anomaly Detected"

        elif failed_attempts >= 5:
            action = "Temporarily Block IP"

        else:
            action = "Alert Administrator"

        print(
            f"IP: {ip} | "
            f"ML: {ml_result} | "
            f"Action: {action}"
        )


if __name__ == "__main__":
    respond_to_threats()