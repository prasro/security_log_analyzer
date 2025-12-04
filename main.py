import sys
from contextlib import suppress

from wrappers.event_analyzer import Analyzer
from wrappers.log_parser import LogParser
from wrappers.report_gen import ReportBuilder


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <logfile>")
        return

    logfile = sys.argv[1]
    parser = LogParser(logfile)
    df = parser.parse_log()

    with suppress(AttributeError):
        if df.empty:
            print("No log entries parsed.")
            return

    analyzer = Analyzer(df)
    incidents = analyzer.run_all()
    ip_dict = analyzer.get_ip_distribution()

    print(f"Detected {len(incidents)} incidents.")
    analyzer.print_summary(incidents)

    # Build HTML report
    report_builder = ReportBuilder(df, incidents, ip_dict)
    report_path = report_builder.build_html_report()
    print(f"HTML report generated: {report_path}")


if __name__ == "__main__":
    main()
