import pandas as pd


class SQLInjectionDetector:
    PATTERNS = ["UNION", "SELECT", "DROP", " OR ", "1=1"]

    def detect(self, df: pd.DataFrame) -> list:
        if df.empty:
            return []

        pattern = "|".join(self.PATTERNS)

        sql_events = df[df["message"].str.contains(pattern, case=False, na=False)]

        incidents = []
        incidents.extend(
            {
                "type": "SQL Injection",
                "source_ip": row["source_ip"],
                "timestamp": str(row["timestamp"]),
                "message": row["message"],
            }
            for _, row in sql_events.iterrows()
        )
        return incidents
