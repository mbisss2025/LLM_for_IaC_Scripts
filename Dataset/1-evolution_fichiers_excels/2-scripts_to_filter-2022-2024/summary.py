import os
import json
import re
import pandas as pd

# Dossier contenant les fichiers JSON de scan
OUTPUT_DIR = r"C:\\Users\\DELL\\Documents\\test_snyk\\test4"
SUMMARY_FILE = os.path.join(OUTPUT_DIR, "snyk_scan_summary.xlsx")

def extract_info_from_filename(filename):
    """
    Extrait le repo, le SHA et le type de scan depuis le nom du fichier
    Ex: snyk-code-repo1-abc1234.json => (repo1, abc1234, code)
    """
    base = os.path.basename(filename)
    match = re.match(r"snyk-(code|iac)-(.+)-([a-f0-9]{7})\.json", base)
    if match:
        scan_type, repo, sha = match.groups()
        return repo, sha, scan_type
    return None, None, None

def count_vulnerabilities(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                if "vulnerabilities" in data:
                    return len(data["vulnerabilities"])
                elif "summary" in data and "totalIssues" in data["summary"]:
                    return data["summary"]["totalIssues"]
    except Exception as e:
        return -1
    return 0

def generate_summary_from_folder(folder):
    entries = []
    for filename in os.listdir(folder):
        if filename.startswith("snyk-") and filename.endswith(".json"):
            full_path = os.path.join(folder, filename)
            repo, sha, scan_type = extract_info_from_filename(filename)
            if repo and sha and scan_type:
                nb_vuln = count_vulnerabilities(full_path)
                entries.append({
                    "repo": repo,
                    "commit_sha": sha,
                    "scan_type": scan_type,
                    "nb_vulnerabilities": nb_vuln,
                    "file": filename
                })
    return pd.DataFrame(entries)

# Génération du résumé
df_summary = generate_summary_from_folder(OUTPUT_DIR)

# Sauvegarde du fichier .xlsx
df_summary.to_excel(SUMMARY_FILE, index=False)
print(f"✅ Résumé exporté : {SUMMARY_FILE}")
