import re
from contextlib import suppress
from pathlib import Path

import pandas as pd


class LogParser:
    """Parses log files into structured DataFrames."""

    LOG_PATTERN = re.compile(
        r"\[(?P<timestamp>[^\]]+)\]\s+"  # timestamp inside brackets
        r"(?P<event_type>\S+)\s+"  # INFO, WARNING, ERROR
        r"(?P<source_ip>\S+)\s+"  # IP Address
        r"(?P<message>.+)"  # everything remaining
    )

    def __init__(self, filepath: str):
        """Initialize the LogParser with file path."""
        self.filepath = Path(filepath)

    def parse_log(self) -> pd.DataFrame:
        """Parse log file and return structured DataFrame."""
        entries = self._extract_entries()
        with suppress(AttributeError):
            if not entries:
                print("No log entries parsed.")
                return pd.DataFrame()

        df = pd.DataFrame(entries)

        # Parse timestamp safely
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        return df

    def _extract_entries(self) -> list[dict]:
        """Extract log entries from file."""
        entries = []

        with suppress(FileNotFoundError):
            with open(self.filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    if match := self.LOG_PATTERN.match(line):
                        entries.append(match.groupdict())

        return entries
