from flask import Flask, render_template, redirect, url_for
import pandas as pd
import os
import sys
import subprocess

app = Flask(__name__)

# Project root folder
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

# Correct report path
REPORT_FILE = os.path.join(
    PROJECT_ROOT,
    "reports",
    "security_report.csv"
)


@app.route("/")
def dashboard():

    if not os.path.exists(REPORT_FILE):
        return "Security report not found. Please run a security scan first."

    report = pd.read_csv(REPORT_FILE)

    total_threats = len(report)

    malware_count = report[
        report["Threat"].str.contains(
            "Malware",
            case=False,
            na=False
        )
    ].shape[0]

    brute_force_count = report[
        report["Threat"].str.contains(
            "Brute Force",
            case=False,
            na=False
        )
    ].shape[0]

    high_traffic_count = report[
        report["Threat"].str.contains(
            "High Traffic",
            case=False,
            na=False
        )
    ].shape[0]

    ml_anomalies = report[
        report["ML Result"] == "Anomaly"
    ].shape[0]

    return render_template(
        "dashboard.html",
        total_threats=total_threats,
        malware_count=malware_count,
        brute_force_count=brute_force_count,
        high_traffic_count=high_traffic_count,
        ml_anomalies=ml_anomalies,
        threats=report.to_dict(orient="records")
    )


@app.route("/scan")
def run_scan():

    main_file = os.path.join(
        PROJECT_ROOT,
        "main.py"
    )

    # Run main.py from project root
    subprocess.run(
        [sys.executable, main_file],
        cwd=PROJECT_ROOT,
        check=True
    )

    return redirect(url_for("dashboard"))


if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )