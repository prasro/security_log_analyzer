import pandas as pd


class BruteForceDetector:
    """Detects brute-force login attempts based on repeated FAILED_LOGIN events."""

    BRUTE_FORCE_THRESHOLD = 3  # number of consecutive failed logins to flag

    def detect(self, df: pd.DataFrame) -> list:
        if df.empty:
            return []

        # Only WARNING or ERROR events for failed logins
        logs = df[df["event_type"].isin(["WARNING", "ERROR"])]

        # Only FAILED_LOGIN messages
        failed = logs[logs["message"].str.contains("FAILED_LOGIN", case=False, na=False)]

        if failed.empty:
            return []

        incidents = []

        # Grouping by IP
        for ip, group in failed.groupby("source_ip"):
            # Sort chronologically
            group = group.sort_values("timestamp").reset_index(drop=True)

            brute_force_count = 1
            for i in range(1, len(group)):
                curr = group.loc[i]
                if curr["message"].startswith("FAILED_LOGIN"):
                    brute_force_count += 1
                else:
                    brute_force_count = 1

                if brute_force_count == self.BRUTE_FORCE_THRESHOLD:
                    incidents.append(
                        {
                            "type": "Brute Force",
                            "source_ip": ip,
                            "timestamp": str(curr["timestamp"]),
                            "message": f"3+ consecutive FAILED_LOGIN attempts from {ip}",
                        }
                    )
                    # reset for next detection
                    brute_force_count = 0
        return incidents
