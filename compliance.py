COMPLIANCE_MAP = {
    "Public Exposure": ("CIS 4.1", "PCI 1.2.1"),
    "Unrestricted Outbound": ("CIS 4.2", "PCI 1.2.3"),
    "Full Port Range": ("CIS 4.1", "PCI 1.2.1"),
    "DB Indirectly Reachable from VPN": ("CIS 4.1", "PCI 1.3.1"),
    "Redis Indirectly Reachable from VPN": ("CIS 4.1", "PCI 1.3.1"),
    "Suspicious Rule": ("CIS 1.1", "PCI 12.2")
}

def map_compliance(findings):
    cis_controls = set()
    pci_controls = set()

    for f in findings:
        if f in COMPLIANCE_MAP:
            cis, pci = COMPLIANCE_MAP[f]
            cis_controls.add(cis)
            pci_controls.add(pci)

    return ", ".join(cis_controls), ", ".join(pci_controls)
