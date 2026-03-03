import pandas as pd

def compare_baseline(old_file, new_file, output):
    old = pd.read_excel(old_file)
    new = pd.read_excel(new_file)

    merged = new.merge(
        old,
        on=["Security Group", "Rule Type", "Port Range", "Source/Destination"],
        how="left",
        indicator=True
    )

    changes = merged[merged["_merge"] == "left_only"]

    changes.to_excel(output, index=False)
    print("[+] Baseline comparison report generated.")
