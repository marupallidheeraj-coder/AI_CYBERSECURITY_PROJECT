from agents.log_analyzer import analyze_logs
from agents.threat_detection import detect_threats
from agents.malware_analysis import analyze_malware
from agents.response_agent import respond_to_threats
from agents.report_generation import generate_report


def main():

    print("\n======================================")
    print(" AI AUTONOMOUS CYBERSECURITY SYSTEM")
    print("======================================")

    print("\n[1] Starting Log Analyzer Agent...")
    analyze_logs()

    print("\n[2] Starting Threat Detection Agent...")
    detect_threats()

    print("\n[3] Starting Malware Analysis Agent...")
    analyze_malware()

    print("\n[4] Starting Response Agent...")
    respond_to_threats()

    print("\n[5] Starting Report Generation Agent...")
    generate_report()

    print("\n======================================")
    print(" SECURITY ANALYSIS COMPLETED")
    print("======================================")


if __name__ == "__main__":
    main()