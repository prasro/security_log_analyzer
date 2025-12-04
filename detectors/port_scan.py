import pandas as pd


class PortScanDetector:
    """Detects repeated connection attempts to multiple ports from a single source."""

    PORT_THRESHOLD = 2  # minimum unique ports to flag as suspicious

    def detect(self, df: pd.DataFrame) -> list:
        if df.empty:
            return []

        # Only WARNING or ERROR events are relevant
        logs = df[df["event_type"].isin(["WARNING", "ERROR"])]

        # Filter port scan attempts
        scans = logs[logs["message"].str.contains("PORT_SCAN|PORT_SCAN_ATTEMPT", case=False)]
        if scans.empty:
            return []

        incidents = []
        for ip, group in scans.groupby("source_ip"):
            ports = group["message"].str.extract(r"(\d+)")[0].unique()
            if len(ports) >= self.PORT_THRESHOLD:
                incidents.append(
                    {
                        "type": "Port Scan",
                        "source_ip": ip,
                        "timestamp": str(group.iloc[0]["timestamp"]),
                        "message": f"Scanned {len(ports)} unique ports: {sorted(ports)}",
                    }
                )

        return incidents
