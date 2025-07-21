import requests
import base64
import pandas as pd
import re
import time
from urllib.parse import quote

# ======== CONFIGURATION ========
GITHUB_TOKEN = "xxx"
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.cloak-preview"
}
KEYWORDS = ["terraform", "ansible", "puppet"]
EXCLUDE_PATTERNS = ["module", "role", "plugin", "ansible/ansible", "puppetlabs/puppet", "hashicorp/terraform"]
# ===============================

def safe_get(url, headers, retries=3, delay=5):
    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=(10, 60))
            return response
        except requests.exceptions.ReadTimeout as e:
            print(f"[Timeout] Lecture en attente (tentative {attempt}/{retries}) -> {url}")
        except requests.exceptions.ConnectionError as e:
            print(f"[Erreur] Connexion echouee ({attempt}/{retries}) : {e}")
        time.sleep(delay)
    print(f"[Erreur] Echec definitif apres {retries} tentatives : {url}")
    return None

def detect_iac_tool(repo):
    name = repo["name"].lower()
    desc = (repo.get("description") or "").lower()
    topics = [t.lower() for t in repo.get("topics", [])]
    iac_keywords = {
        "Terraform": ["terraform", ".tf", "main.tf", "provider", "resource"],
        "Ansible": ["ansible", "playbook", ".yml", "site.yml", "roles"],
        "Puppet": ["puppet", ".pp", "manifest", "site.pp", "nodes"]
    }
    for tool, keywords in iac_keywords.items():
        if any(kw in name or kw in desc for kw in keywords) or tool.lower() in topics:
            return tool
    return "Unknown"
    

def search_valid_repositories(keyword, max_pages=20, per_page=50, delay=3):
    print(f"\n[Recherche] Recherche elargie pour : {keyword}")
    all_repos = []
    seen_repos = set()

    search_queries = [
        f"topic:{keyword}",
        f'"using {keyword}" in:description',
        f'"Infrastructure as Code" in:description',
    ]

    for query in search_queries:
        for page in range(1, max_pages + 1):
            url = f"https://api.github.com/search/repositories?q={quote(query)}+stars:>30&sort=stars&order=desc&per_page={per_page}&page={page}"
            response = safe_get(url, headers=HEADERS)
            if response is None:
                break

            repos = response.json().get("items", [])
            for repo in repos:
                full_name = repo["full_name"].lower()
                description = (repo.get("description") or "").lower()

                if full_name in seen_repos:
                    continue
                if any(excl in full_name for excl in EXCLUDE_PATTERNS):
                    continue
                if any(bad in description for bad in ["example", "sample", "test", "learn", "tutorial", "demo", "education"]):
                    continue

                repo["tool_used"] = detect_iac_tool(repo)
                seen_repos.add(full_name)
                all_repos.append(repo)

            time.sleep(delay)
    return all_repos

def search_security_commits(repo_full_name, max_pages=2):
    results = []
    patterns = ["CVE-", "security", "vulnerability", "exploit", "patch"]
    for pattern in patterns:
        for page in range(1, max_pages + 1):
            url = f"https://api.github.com/search/commits?q={quote(pattern)}+repo:{repo_full_name}&per_page=20&page={page}"
            response = safe_get(url, headers=HEADERS)
            if response is None:
                continue
            items = response.json().get("items", [])
            for item in items:
                commit = {
                    "sha": item["sha"],
                    "message": item["commit"]["message"],
                    "type": "CVE" if "CVE-" in item["commit"]["message"] else "Security"
                }
                results.append(commit)
    return results

def get_commit_files(repo_full_name, sha):
    url = f"https://api.github.com/repos/{repo_full_name}/commits/{sha}"
    response = safe_get(url, headers=HEADERS)
    if response is None:
        return {}
    return response.json()

def extract_changed_lines(patch):
    if not patch:
        return []
    lines = patch.splitlines()
    results = []
    current_diff = None
    before_lines, after_lines = [], []

    for line in lines:
        if line.startswith('@@'):
            if current_diff:
                results.append((current_diff, '\n'.join(before_lines), '\n'.join(after_lines)))
                before_lines, after_lines = [], []
            current_diff = line
        elif line.startswith('-') and not line.startswith('---'):
            before_lines.append(line[1:])
        elif line.startswith('+') and not line.startswith('+++'):
            after_lines.append(line[1:])
        else:
            before_lines.append(line)
            after_lines.append(line)

    if current_diff:
        results.append((current_diff, '\n'.join(before_lines), '\n'.join(after_lines)))

    return results

# === MAIN SCRIPT ===
dataset = []
seen_diffs = set()

for keyword in KEYWORDS:
    repositories = search_valid_repositories(keyword)

    for repo in repositories:
        full_name = repo["full_name"]
        tool = repo.get("tool_used", "Unknown")
        print(f"\n[Repository] {full_name} | Tool: {tool}")

        security_commits = search_security_commits(full_name)
        for commit in security_commits:
            sha = commit["sha"]
            message = commit["message"]
            commit_type = commit["type"]
            commit_url = f"https://github.com/{full_name}/commit/{sha}"

            commit_data = get_commit_files(full_name, sha)
            files = commit_data.get("files", [])

            for file in files:
                filepath = file.get("filename", "")
                patch = file.get("patch", "")
                if not patch or not filepath.endswith((".tf", ".pp", ".yml", ".yaml")):
                    continue

                blocks = extract_changed_lines(patch)
                for diff_header, code_before, code_after in blocks:
                    if diff_header in seen_diffs:
                        continue
                    seen_diffs.add(diff_header)

                    dataset.append({
                        "Commit URL": commit_url,
                        "Filepath": filepath,
                        "Diff": diff_header,
                        "Code Before": code_before,
                        "Code After": code_after,
                        "Commit Message": message,
                        "Tool Used": tool
                    })

# === EXPORT ===
df = pd.DataFrame(dataset)
df.to_excel("iac_security_commits.xlsx", index=False)
print(f"\n[Export] {len(df)} entrees enregistrees dans iac_security_commits.xlsx")
