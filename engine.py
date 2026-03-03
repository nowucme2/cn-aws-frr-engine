import pandas as pd
import ipaddress
from collections import defaultdict
from compliance import map_compliance
from reporter import generate_excel_report, generate_html_dashboard

STRICT_PCI_MODE = True

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

def get_port_weight(port):
    if port in PORT_RISK:
        return PORT_RISK[port]
    if "-" in port:
        start, end = port.split("-")
        if start == "0" and end == "65535":
            return 10
        if int(end) - int(start) > 20000:
            return 7
    return 3

def get_cidr_weight(cidr):
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

def build_graph(df):
    graph = defaultdict(set)
    for _, row in df.iterrows():
        if str(row["Rule Type"]).lower() == "inbound":
            src = str(row["Source/Destination"])
            dest = str(row["Security Group"])
            if "sg-" in src:
                graph[src].add(dest)
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

def analyze(df):
    graph = build_graph(df)
    results = []

    for _, row in df.iterrows():
        score = 0
        findings = []
        rule_type = str(row["Rule Type"]).lower()
        port = str(row["Port Range"])
        source = str(row["Source/Destination"])
        sg = str(row["Security Group"])
        desc = str(row.get("Description", "")).lower()

        score += get_port_weight(port)

        if "/" in source:
            score += get_cidr_weight(source)
            if is_public(source):
                score += 5
                findings.append("Public Exposure")

        if rule_type == "inbound":
            score += 3

        if rule_type == "outbound" and source == "0.0.0.0/0":
            score += 5
            findings.append("Unrestricted Outbound")

        if port in ["All", "0-65535"]:
            score += 6
            findings.append("Full Port Range")

        if any(x in desc for x in ["delete", "tmp", "test"]):
            score += 5
            findings.append("Suspicious Rule")

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

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python engine.py input.xlsx output.xlsx")
        exit()

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    df = pd.read_excel(input_file)
    analyzed = analyze(df)

    generate_excel_report(analyzed, output_file)
    generate_html_dashboard(analyzed, "dashboard.html")

    print("[+] Enterprise AWS FRR analysis complete.")
