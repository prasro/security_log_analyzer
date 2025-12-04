import pandas as pd


class UnusualAccessDetector:
    """Detects access to sensitive system files/directories."""

    SENSITIVE_PATHS = ["/etc/", "/root/", "/var/", "/admin/"]

    def detect(self, df: pd.DataFrame) -> list:
        if df.empty:
            return []

        # Only ERROR
        logs = df[df["event_type"].isin(["ERROR"])]
        pattern = "|".join(self.SENSITIVE_PATHS)

        matches = logs[logs["message"].str.contains(pattern, case=False, na=False)]

        return [
            {
                "type": "Unusual Access",
                "source_ip": row["source_ip"],
                "timestamp": str(row["timestamp"]),
                "message": row["message"],
            }
            for _, row in matches.iterrows()
        ]
