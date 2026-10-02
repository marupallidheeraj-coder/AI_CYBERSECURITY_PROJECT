from flask import Flask, render_template, redirect, url_for
import pandas as pd
import os
import sys

app = Flask(__name__)

REPORT_FILE = "../reports/security_report.csv"


@app.route("/")
def dashboard():

    if not os.path.exists(REPORT_FILE):
        return "Security report not found. Please run a security scan first."

    report = pd.read_csv(REPORT_FILE)

    total_threats = len(report)

    malware_count = report[
        report["Threat"].str.contains("Malware", case=False, na=False)
    ].shape[0]

    brute_force_count = report[
        report["Threat"].str.contains("Brute Force", case=False, na=False)
    ].shape[0]

    high_traffic_count = report[
        report["Threat"].str.contains("High Traffic", case=False, na=False)
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

    # Go to project root
    project_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )

    # Run main.py
    os.system(
        f'"{sys.executable}" "{os.path.join(project_root, "main.py")}"'
    )

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True)