import pandas as pd
import ipaddress
from collections import defaultdict
from compliance import map_compliance
from reporter import generate_excel_report, generate_html_dashboard

STRICT_PCI_MODE = True

# -------------------------
# PORT RISK MODEL
# -------------------------

PORT_RISK = {
    "3306": 9, "5432": 9, "5439": 9, "1433": 9,
    "6379": 9,
    "22": 8, "3389": 8,
    "500": 7, "4500": 7, "1701": 7,
    "61617": 8, "8162": 8,
    "9200": 9,
    "6443": 10,
    "25": 5, "587": 5,
    "80": 4,
    "443": 2
}

DB_PORTS = ["3306", "5432", "5439", "1433"]
CACHE_PORTS = ["6379"]

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
        "PortRange": "Port Range",
        "From Port": "Port Range",
        "Source": "Source/Destination",
        "Destination": "Source/Destination",
        "SecurityGroup": "Security Group",
        "SecurityGroupId": "Security Group"
    }

    df.rename(columns=rename_map, inplace=True)
    return df

# -------------------------
# HELPER FUNCTIONS
# -------------------------

def safe_str(value):
    if pd.isna(value):
        return ""
    return str(value).strip()

def get_port_weight(port):
    port = safe_str(port)

    if port in PORT_RISK:
        return PORT_RISK[port]

    if "-" in port:
        try:
            start, end = port.split("-")
            if start == "0" and end == "65535":
                return 10
            if int(end) - int(start) > 20000:
                return 7
        except:
            pass

    if port.lower() == "all":
        return 10

    return 3

def get_cidr_weight(cidr):
    cidr = safe_str(cidr)

    if "/" not in cidr:
        return 2

    try:
        net = ipaddress.ip_network(cidr, strict=False)
        prefix = net.prefixlen

        if prefix == 0:
            return 10
        if prefix <= 8:
            return 8
        if prefix <= 16:
            return 6
        if prefix <= 24:
            return 3
        return 1
    except:
        return 2

def is_public(cidr):
    try:
        return not ipaddress.ip_network(cidr, strict=False).is_private
    except:
        return False

def classify(score):
    if score >= 18:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 7:
        return "Medium"
    return "Low"

# -------------------------
# GRAPH BUILDER
# -------------------------

def build_graph(df):
    graph = defaultdict(set)

    for _, row in df.iterrows():
        rule_type = safe_str(row.get("Rule Type")).lower()
        source = safe_str(row.get("Source/Destination"))
        dest = safe_str(row.get("Security Group"))

        if rule_type == "inbound" and "sg-" in source:
            graph[source].add(dest)

    return graph

def detect_indirect_vpn(graph, target, visited=None):
    if visited is None:
        visited = set()

    if target in visited:
        return False

    visited.add(target)

    for src, dests in graph.items():
        if target in dests:
            if "vpn" in src.lower():
                return True
            if detect_indirect_vpn(graph, src, visited):
                return True

    return False

# -------------------------
# MAIN ANALYSIS ENGINE
# -------------------------

def analyze(df):
    graph = build_graph(df)
    results = []

    for _, row in df.iterrows():

        score = 0
        findings = []

        rule_type = safe_str(row.get("Rule Type")).lower()
        port = safe_str(row.get("Port Range"))
        source = safe_str(row.get("Source/Destination"))
        sg = safe_str(row.get("Security Group"))
        desc = safe_str(row.get("Description")).lower()

        # Port Risk
        score += get_port_weight(port)

        # CIDR Risk
        if "/" in source:
            score += get_cidr_weight(source)
            if is_public(source):
                score += 5
                findings.append("Public Exposure")

        # Inbound Amplifier
        if rule_type == "inbound":
            score += 3

        # Outbound Risk
        if rule_type == "outbound" and source == "0.0.0.0/0":
            score += 5
            findings.append("Unrestricted Outbound")

        # Full Port Range
        if port.lower() in ["all", "0-65535"]:
            score += 6
            findings.append("Full Port Range")

        # Suspicious Rule
        if any(word in desc for word in ["delete", "tmp", "test"]):
            score += 5
            findings.append("Suspicious Rule")

        # Indirect VPN Exposure
        if port in DB_PORTS and detect_indirect_vpn(graph, sg):
            score += 7
            findings.append("DB Indirectly Reachable from VPN")

        if port in CACHE_PORTS and detect_indirect_vpn(graph, sg):
            score += 7
            findings.append("Redis Indirectly Reachable from VPN")

        severity = classify(score)

        cis, pci = map_compliance(findings)

        if STRICT_PCI_MODE:
            pci_status = "FAIL" if severity in ["Critical", "High"] else "PASS"
        else:
            pci_status = "REVIEW"

        results.append({
            **row,
            "Risk Score": score,
            "Severity": severity,
            "Findings": ", ".join(findings) if findings else "No Immediate Risk",
            "CIS Control": cis,
            "PCI DSS Requirement": pci,
            "PCI Compliance Status": pci_status
        })

    return pd.DataFrame(results)

# -------------------------
# ENTRY POINT
# -------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python engine.py input.xlsx output.xlsx")
        exit()

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    print("[+] Loading Excel...")
    df = pd.read_excel(input_file)

    print("[+] Normalizing Columns...")
    df = normalize_columns(df)

    print("[+] Running Advanced FRR Analysis...")
    analyzed_df = analyze(df)

    print("[+] Generating Reports...")
    generate_excel_report(analyzed_df, output_file)
    generate_html_dashboard(analyzed_df, "dashboard.html")

    print("[+] Analysis Complete.")
