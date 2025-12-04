import base64
import os
from io import BytesIO

import matplotlib.pyplot as plt
import pandas as pd
from jinja2 import Environment, FileSystemLoader


class ReportBuilder:
    def __init__(self, df, incidents, ip_dict, output_dir="output"):
        self.df = df
        self.ip_dict = ip_dict
        self.incidents = incidents
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def base64_plotting(self, fig):
        buf = BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight")
        plt.close(fig)
        buf.seek(0)
        return base64.b64encode(buf.read()).decode("utf-8")

    def chart_attack_distribution(self):
        types = [i["type"] for i in self.incidents]
        if not types:
            return None

        fig, ax = plt.subplots(figsize=(6, 6))
        pd.Series(types).value_counts().plot(kind="pie", autopct="%1.1f%%", ax=ax)
        ax.set_ylabel("")
        ax.set_title("Attack Distribution")
        return self.base64_plotting(fig)

    def chart_attacks_per_ip(self):
        ip_counts = self.ip_dict
        if not ip_counts:
            return None

        fig, ax = plt.subplots(figsize=(10, 5))
        pd.Series(ip_counts).sort_values(ascending=False).plot(kind="bar", color="steelblue", ax=ax)
        ax.set_title("Attacks per Source IP")
        ax.set_xlabel("IP Address")
        ax.set_ylabel("Count")
        return self.base64_plotting(fig)

    # REPORT
    def build_html_report(self, output_file="report.html"):
        env = Environment(loader=FileSystemLoader("templates"))
        template = env.get_template("report_template.html")

        html_content = template.render(
            total_incidents=len(self.incidents),
            incidents=self.incidents,
            chart_distribution=self.chart_attack_distribution(),
            chart_per_ip=self.chart_attacks_per_ip(),
        )

        out_path = os.path.join(self.output_dir, output_file)
        with open(out_path, "w") as f:
            f.write(html_content)

        return out_path
