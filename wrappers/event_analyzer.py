from collections import defaultdict

from detectors.access_detect import UnusualAccessDetector
from detectors.brute_force_detect import BruteForceDetector
from detectors.ip_attack_counts import IPDistribution
from detectors.port_scan import PortScanDetector
from detectors.sql_injection_detect import SQLInjectionDetector


class Analyzer:
    def __init__(self, df):
        self.df = df
        self.detectors = [
            BruteForceDetector(),
            SQLInjectionDetector(),
            UnusualAccessDetector(),
            PortScanDetector(),
        ]

    def run_all(self):
        results = []
        for detector in self.detectors:
            output = detector.detect(self.df)
            if isinstance(output, dict):
                for ip, entry in output.items():
                    entry["source_ip"] = ip
                    results.append(entry)
            elif isinstance(output, list):
                results.extend(output)
        return results

    def print_summary(self, incidents):
        """Print a grouped summary of incidents to the terminal with a security warning if needed."""
        if not incidents:
            print("No incidents detected.")
            return

        print("\n=== Incident Summary ===")
        summary = defaultdict(int)

        for inc in incidents:
            summary[inc["type"]] += 1

        for itype, count in summary.items():
            print(f"{itype}: {count}")

        # Check for security threats
        threats = {"Brute Force", "SQL Injection", "Unusual Access", "Port Scan"}
        found_threat = any(itype in threats for itype in summary)

        if found_threat:
            print("SECURITY THREAT DETECTED! Please review the detailed HTML report.")
        else:
            print("No major security threats detected.")

        print("========================\n")

    def get_ip_distribution(self):
        """Return a dictionary of source IP event count."""
        ip_dist = IPDistribution(self.df)
        return ip_dist.get_distribution()
