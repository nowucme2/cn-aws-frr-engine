import pandas as pd

def generate_excel_report(df, output):
    with pd.ExcelWriter(output) as writer:
        df.to_excel(writer, sheet_name="Detailed Findings", index=False)

        summary = df["Severity"].value_counts().reset_index()
        summary.columns = ["Severity", "Count"]
        summary.to_excel(writer, sheet_name="Executive Summary", index=False)

        critical = df[df["Severity"] == "Critical"]
        critical.to_excel(writer, sheet_name="Critical Findings", index=False)

        cis_summary = df.groupby("CIS Control").size().reset_index(name="Count")
        cis_summary.to_excel(writer, sheet_name="CIS Mapping", index=False)

        pci_summary = df.groupby("PCI DSS Requirement").size().reset_index(name="Count")
        pci_summary.to_excel(writer, sheet_name="PCI Mapping", index=False)

def generate_html_dashboard(df, output_html):
    summary = df["Severity"].value_counts()

    html = f"""
    <html>
    <head>
    <title>AWS FRR Dashboard</title>
    </head>
    <body>
    <h1>AWS FRR Compliance Dashboard</h1>
    <ul>
        <li>Critical: {summary.get("Critical",0)}</li>
        <li>High: {summary.get("High",0)}</li>
        <li>Medium: {summary.get("Medium",0)}</li>
        <li>Low: {summary.get("Low",0)}</li>
    </ul>
    </body>
    </html>
    """

    with open(output_html, "w") as f:
        f.write(html)
