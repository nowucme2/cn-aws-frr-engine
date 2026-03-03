import pandas as pd
import ipaddress
from collections import defaultdict
from compliance import map_compliance
from reporter import generate_excel_report, generate_html_dashboard

STRICT_PCI_MODE = True

SENSITIVE_PORTS = [
    "3306", "5432", "5439", "1433",
    "6379", "22", "3389",
    "9200", "6443"
]

LOW_RISK_OUTBOUND = ["53", "123", "443"]


# -------------------------
# COLUMN NORMALIZATION
# -------------------------

def normalize_columns(df):
    df.columns = df.columns.str.strip()

    rename_map = {
        "Type": "Rule Type",
        "Direction": "Rule Type",
        "rule_type": "Rule Type",
        "Port": "Port Range",
        "From Port": "Port Range",
        "Source": "Source/Destination",
        "Destination": "Source/Destination",
        "SecurityGroup": "Security Group",
        "SecurityGroupId": "Security Group"
    }

    df.rename(columns=rename_map, inplace=True)
    return df


def safe(value):
    if pd.isna(value):
        return ""
    return str(value).strip()


def is_public(cidr):
    try:
        return not ipaddress.ip_network(cidr, strict=False).is_private
    except:
        return False


def cidr_prefix(cidr):
    try:
        return ipaddress.ip_network(cidr, strict=False).prefixlen
    except:
        return 32


# -------------------------
# GRAPH BUILDER
# -------------------------

def build_graph(df):
    graph = defaultdict(set)

    for _, row in df.iterrows():
        rule_type = safe(row.get("Rule Type")).lower()
        source = safe(row.get("Source/Destination"))
        dest = safe(row.get("Security Group"))

        if rule_type == "inbound" and "sg-" in source:
            graph[source].add(dest)

    return graph


# -------------------------
# RECOMMENDATION ENGINE
# -------------------------

def generate_recommendation(findings):
    rec = []

    for f in findings:
        if f == "Public Sensitive Service Exposure":
            rec.append("Restrict access to internal network or VPN only.")
        elif f == "Public Full Port Exposure":
            rec.append("Remove full port exposure and allow only required services.")
        elif f == "Public Service Exposure":
            rec.append("Limit exposure to trusted IP addresses.")
        elif f == "Sensitive Service Reachable from VPN":
            rec.append("Restrict sensitive services to application security groups only.")
        elif f == "Full Port Range Exposure":
            rec.append("Replace full port rule with specific required ports.")
        elif f == "Unrestricted Outbound Access":
            rec.append("Restrict outbound access to required destinations only.")
        elif f == "Wide Internal CIDR Exposure":
            rec.append("Reduce internal CIDR scope to least privilege segmentation.")
        elif f == "Suspicious Rule":
            rec.append("Remove temporary or test rules.")

    if not rec:
        return "No action required."

    return " | ".join(set(rec))


# -------------------------
# MAIN ANALYSIS
# -------------------------

def analyze(df):
    graph = build_graph(df)
    results = []

    for _, row in df.iterrows():

        rule_type = safe(row.get("Rule Type")).lower()
        port = safe(row.get("Port Range"))
        source = safe(row.get("Source/Destination"))
        sg = safe(row.get("Security Group"))
        desc = safe(row.get("Description")).lower()

        findings = []
        severity = "Low"

        # -------- PUBLIC INBOUND --------

        if rule_type == "inbound" and "/" in source:
            prefix = cidr_prefix(source)

            if is_public(source):

                if source == "0.0.0.0/0":
                    if port in SENSITIVE_PORTS:
                        severity = "Critical"
                        findings.append("Public Sensitive Service Exposure")
                    elif port.lower() in ["all", "0-65535"]:
                        severity = "Critical"
                        findings.append("Public Full Port Exposure")
                    else:
                        severity = "High"
                        findings.append("Public Service Exposure")

                elif prefix == 32:
                    severity = "High"
                    findings.append("Public Sensitive Service Exposure")

                else:
                    severity = "High"
                    findings.append("Public Service Exposure")

            elif prefix <= 8:
                severity = "High"
                findings.append("Wide Internal CIDR Exposure")

        # -------- FULL PORT RANGE --------

        if port.lower() in ["all", "0-65535"] and severity != "Critical":
            severity = "High"
            findings.append("Full Port Range Exposure")

        # -------- VPN PATH TO SENSITIVE --------

        if port in SENSITIVE_PORTS:
            for src, dests in graph.items():
                if sg in dests and "vpn" in src.lower():
                    if severity != "Critical":
                        severity = "High"
                    findings.append("Sensitive Service Reachable from VPN")

        # -------- OUTBOUND --------

        if rule_type == "outbound" and source == "0.0.0.0/0":

            if port in LOW_RISK_OUTBOUND:
                severity = "Low"

            elif port.lower() in ["all", "0-65535"]:
                severity = "Medium"
                findings.append("Unrestricted Outbound Access")

            else:
                severity = "Medium"
                findings.append("Outbound Internet Exposure")

        # -------- SUSPICIOUS --------

        if any(x in desc for x in ["delete", "tmp", "test"]):
            severity = "Medium"
            findings.append("Suspicious Rule")

        if not findings:
            findings.append("No Immediate Risk")

        recommendation = generate_recommendation(findings)
        cis, pci = map_compliance(findings)

        pci_status = "FAIL" if STRICT_PCI_MODE and severity in ["Critical", "High"] else "PASS"

        results.append({
            **row,
            "Severity": severity,
            "Findings": ", ".join(findings),
            "Recommendation": recommendation,
            "CIS Control": cis,
            "PCI DSS Requirement": pci,
            "PCI Compliance Status": pci_status
        })

    return pd.DataFrame(results)


# -------------------------
# ATTACK PATH SHEET
# -------------------------

def generate_attack_path_sheet(df):

    attack_paths = []

    for _, row in df.iterrows():
        if row["Severity"] in ["Critical", "High"]:
            attack_paths.append({
                "Security Group": row["Security Group"],
                "Port": row["Port Range"],
                "Source": row["Source/Destination"],
                "Attack Scenario": f"Potential attack path from {row['Source/Destination']} to {row['Security Group']} on port {row['Port Range']}"
            })

    return pd.DataFrame(attack_paths)


# -------------------------
# MAIN ENTRY
# -------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python engine.py input.xlsx output.xlsx")
        exit()

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    df = pd.read_excel(input_file)
    df = normalize_columns(df)

    analyzed = analyze(df)
    attack_sheet = generate_attack_path_sheet(analyzed)

    # Generate main structured report
    generate_excel_report(analyzed, output_file)

    # Append attack path sheet
    with pd.ExcelWriter(output_file, mode="a", engine="openpyxl") as writer:
        attack_sheet.to_excel(writer, sheet_name="Attack Paths", index=False)

    generate_html_dashboard(analyzed, "dashboard.html")

    print("[+] Final enterprise analysis complete.")
