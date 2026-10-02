import pandas as pd
from sklearn.ensemble import IsolationForest
import os

LOG_FILE = "data/security_logs.csv"
MODEL_FILE = "models/isolation_forest_model.pkl"


def train_model():

    logs = pd.read_csv(LOG_FILE)

    # Features used for anomaly detection
    features = logs[
        ["failed_attempts", "request_count"]
    ]

    # Create Isolation Forest model
    model = IsolationForest(
        n_estimators=100,
        contamination=0.3,
        random_state=42
    )

    # Train model
    model.fit(features)

    # Predict anomalies
    logs["ML_Prediction"] = model.predict(features)

    # -1 = anomaly, 1 = normal
    logs["ML_Result"] = logs["ML_Prediction"].apply(
        lambda x: "Anomaly" if x == -1 else "Normal"
    )

    print("\n===== MACHINE LEARNING THREAT DETECTION =====")

    print(
        logs[
            [
                "source_ip",
                "failed_attempts",
                "request_count",
                "ML_Result"
            ]
        ].to_string(index=False)
    )

    # Save model
    os.makedirs("models", exist_ok=True)

    import joblib
    joblib.dump(model, MODEL_FILE)

    print("\nML model saved successfully.")
    print(f"Model file: {MODEL_FILE}")


if __name__ == "__main__":
    train_model()