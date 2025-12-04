from collections import Counter

import pandas as pd


class IPDistribution:
    """Generates a distribution of events per source IP directly from a DataFrame."""

    def __init__(self, df: pd.DataFrame):
        self.df = df

    def get_distribution(self) -> dict:
        """
        Return a dictionary {source_ip: count} from the DataFrame.
        """
        if self.df.empty or "source_ip" not in self.df.columns:
            return {}

        # Use Counter for counting occurrences
        ip_counts = Counter(self.df["source_ip"].dropna())
        return dict(ip_counts)
