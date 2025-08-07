import os
import subprocess
import json
import shutil # Pour shutil.which
import sys
import stat
import pandas as pd

# === CONFIGURATION ===
# Répertoire où les rapports Snyk JSON seront sauvegardés
OUTPUT_DIR = "."
# Fichier Excel contenant les informations des dépôts et commits à scanner
EXCEL_FILE = "salt2.xlsx"  # Adaptez ce nom de fichier si nécessaire
# Répertoire parent où tous vos dépôts clonés se trouvent
REPOS_PARENT_DIR = "." # Par défaut, le répertoire courant. Adaptez si vos dépôts sont ailleurs.
                       # Exemple pour WSL: "/home/mbissine/saltstack" si le script est lancé depuis là

# Noms des colonnes dans votre fichier Excel
REPO_FOLDER_NAME_COLUMN = "nom_dossier" # Colonne contenant le nom du dossier du dépôt local
COMMIT_SHA_COLUMN = "commit_sha"       # Colonne contenant le SHA du commit

CACHE_FILE = os.path.join(OUTPUT_DIR, "scan_specific_commits_cache.json")

# S'assurer que le dossier de sortie pour les rapports Snyk existe
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Trouver le chemin de Git
GIT_PATH = shutil.which("git")
if not GIT_PATH:
    print("ERREUR CRITIQUE : Commande 'git' non trouvée. Veuillez l'installer et l'ajouter au PATH.")
    sys.exit(1)
else:
    print(f"Utilisation de git trouvé à : {GIT_PATH}")

# Trouver le chemin de Snyk
SNYK_PATH = shutil.which("snyk")
if not SNYK_PATH:
    print("ERREUR CRITIQUE : Commande 'snyk' non trouvée. Veuillez l'installer et l'authentifier.")
    sys.exit(1)
else:
    print(f"Utilisation de snyk trouvé à : {SNYK_PATH}")


# === UTILS ===
def handle_remove_readonly(func, path, exc): # Peut être utile si des scripts futurs suppriment des dossiers
    import errno
    excvalue = exc[1]
    if func in (os.rmdir, os.remove, os.unlink) and excvalue.errno in (errno.EACCES, errno.EPERM):
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except Exception:
            pass
    else:
        raise

def safe_run_snyk_command(snyk_args, output_file, cwd):
    """Exécute une commande Snyk et sauvegarde la sortie."""
    try:
        full_command = [SNYK_PATH] + snyk_args
        print(f"    Exécution Snyk : {' '.join(full_command)}")
        result = subprocess.run(full_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, cwd=cwd, text=True, encoding='utf-8', errors='ignore')
        
        json_output_valid = False
        # Tenter de sauvegarder en JSON si la sortie stdout semble en être une
        if result.stdout and (result.stdout.strip().startswith("{") or result.stdout.strip().startswith("[")):
            try:
                json_data = json.loads(result.stdout)
                with open(output_file, "w", encoding="utf-8") as fout:
                    json.dump(json_data, fout, indent=2)
                print(f"    Scan Snyk terminé, résultat JSON sauvegardé dans {output_file}")
                json_output_valid = True
                # Snyk retourne 0 pour "pas de vulnérabilités", 1 pour "vulnérabilités trouvées", >1 pour erreurs.
                return True # La commande s'est exécutée, le JSON est sauvegardé.
            except json.JSONDecodeError:
                print(f"    Avertissement : La sortie Snyk (stdout) ressemblait à du JSON mais n'a pas pu être parsée.")
        
        if not json_output_valid or result.stderr: # Si pas de JSON valide sur stdout OU si stderr n'est pas vide
             with open(output_file, "w", encoding="utf-8") as fout:
                output_content = []
                if result.stdout:
                    output_content.append("STDOUT:\n" + result.stdout)
                if result.stderr:
                    output_content.append("STDERR:\n" + result.stderr)
                if not output_content:
                    output_content.append("Sortie Snyk vide (stdout et stderr).")
                fout.write("\n\n".join(output_content))
            
             if not json_output_valid: 
                 print(f"    Scan Snyk terminé, sortie brute sauvegardée dans {output_file}")

        if result.returncode > 1 : 
             print(f"    ❌ Erreur Snyk (code {result.returncode}). Détails dans {output_file}")
             return False
        
        return True

    except Exception as e:
        print(f"    ❌ Exception Python lors de l'exécution de Snyk : {e}")
        with open(output_file, "w", encoding="utf-8") as fout:
            json.dump({"python_error": str(e), "command": " ".join(full_command if 'full_command' in locals() else snyk_args)}, fout, indent=2)
        return False

# === CACHE ===
def load_scan_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"Avertissement : Le fichier cache '{CACHE_FILE}' est corrompu. Un nouveau cache sera créé.")
            return {}
    return {}

def save_scan_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)

scan_cache = load_scan_cache()

# === SCAN ===
def run_snyk_scan_on_commit(repo_folder_name, commit_sha):
    short_sha = str(commit_sha)[:7]
    abs_repo_path = os.path.abspath(os.path.join(REPOS_PARENT_DIR, repo_folder_name))
    
    repo_cache = scan_cache.get(abs_repo_path, {})
    sha_cache = repo_cache.get(str(commit_sha), {})

    # Utiliser repo_folder_name pour le nom de fichier de sortie, après nettoyage
    output_repo_name_cleaned = repo_folder_name.replace("/", "_").replace("\\", "_")
    code_output = os.path.join(OUTPUT_DIR, f"snyk-code-{output_repo_name_cleaned}-{short_sha}.json")
    iac_output = os.path.join(OUTPUT_DIR, f"snyk-iac-{output_repo_name_cleaned}-{short_sha}.json")

    if sha_cache.get("code_scanned_successfully") and sha_cache.get("iac_scanned_successfully"):
        print(f"✅ Déjà scanné avec succès : {repo_folder_name}@{short_sha}")
        return
    if sha_cache.get("checkout_error"):
        print(f"⚠️  Checkout précédemment échoué pour {repo_folder_name}@{short_sha}. Scan ignoré. Erreur: {sha_cache.get('checkout_error')}")
        return
    if sha_cache.get("repo_not_found_locally"):
        print(f"⚠️  Dépôt {repo_folder_name} marqué comme non trouvé localement. Scan ignoré.")
        return

    if not os.path.isdir(abs_repo_path) or not os.path.isdir(os.path.join(abs_repo_path, ".git")):
        print(f"❌ Dépôt '{repo_folder_name}' non trouvé à '{abs_repo_path}' ou n'est pas un dépôt Git valide. Scan ignoré.")
        scan_cache.setdefault(abs_repo_path, {}).setdefault(str(commit_sha), {})
        scan_cache[abs_repo_path][str(commit_sha)]["repo_not_found_locally"] = True
        scan_cache[abs_repo_path][str(commit_sha)]["code_scanned_successfully"] = False
        scan_cache[abs_repo_path][str(commit_sha)]["iac_scanned_successfully"] = False
        return

    print(f"📂 Utilisation du dépôt local : {abs_repo_path}")
    
    clean_env = os.environ.copy()
    for git_var in ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_OBJECT_DIRECTORY']:
        if git_var in clean_env:
            del clean_env[git_var]

    try:
        print(f"    Configuration de safe.directory pour '{abs_repo_path}'...")
        config_command = [GIT_PATH, "config", "--global", "--add", "safe.directory", abs_repo_path]
        config_result = subprocess.run(config_command, capture_output=True, text=True, check=False, encoding='utf-8', errors='ignore', env=clean_env)
        if config_result.returncode != 0:
            # Si safe.directory existe déjà, la commande peut retourner 5. On l'ignore.
            if config_result.returncode == 5:
                 print(f"    Info: '{abs_repo_path}' est probablement déjà dans safe.directory.")
            else:
                 print(f"    Avertissement lors de 'git config safe.directory': RC={config_result.returncode}, {config_result.stderr.strip()}")
    except Exception as e_conf:
         print(f"    Avertissement lors de la config safe.directory : {e_conf}")

    try:
        print(f"    Nettoyage du dépôt avant checkout...")
        subprocess.run([GIT_PATH, "reset", "--hard", "HEAD"], cwd=abs_repo_path, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean_env)
        subprocess.run([GIT_PATH, "clean", "-fdx"], cwd=abs_repo_path, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean_env)
        print(f"    Nettoyage terminé.")
    except subprocess.CalledProcessError as e:
        print(f"⚠️  Avertissement lors du nettoyage du dépôt {repo_folder_name}: {e.stderr.decode('utf-8', errors='ignore') if e.stderr else e.stdout.decode('utf-8', errors='ignore')}")

    print(f"    Checkout du commit : {commit_sha}...")
    checkout_command = [GIT_PATH, "checkout", "-f", str(commit_sha)]
    checkout_result = subprocess.run(checkout_command, cwd=abs_repo_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='ignore', env=clean_env)
    
    scan_cache.setdefault(abs_repo_path, {}).setdefault(str(commit_sha), {})

    if checkout_result.returncode != 0:
        checkout_error_msg = checkout_result.stderr.strip()
        print(f"    ❌ Erreur lors du checkout du commit {commit_sha} : {checkout_error_msg}")
        print(f"    Tentative de `git fetch`...")
        fetch_command = [GIT_PATH, "fetch", "origin", "--tags", "--force", "--prune"]
        subprocess.run(fetch_command, cwd=abs_repo_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean_env)
        
        checkout_result_after_fetch = subprocess.run(checkout_command, cwd=abs_repo_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='ignore', env=clean_env)
        if checkout_result_after_fetch.returncode != 0:
            error_msg_after_fetch = checkout_result_after_fetch.stderr.strip()
            print(f"    ❌ Échec du checkout même après fetch : {error_msg_after_fetch}")
            scan_cache[abs_repo_path][str(commit_sha)]["checkout_error"] = error_msg_after_fetch
            scan_cache[abs_repo_path][str(commit_sha)]["code_scanned_successfully"] = False
            scan_cache[abs_repo_path][str(commit_sha)]["iac_scanned_successfully"] = False
            return 
        else:
            print(f"    Checkout de {commit_sha} réussi après fetch.")
            if "checkout_error" in scan_cache[abs_repo_path][str(commit_sha)]:
                del scan_cache[abs_repo_path][str(commit_sha)]["checkout_error"]
    else:
        print(f"    Checkout de {commit_sha} réussi.")
        if "checkout_error" in scan_cache[abs_repo_path][str(commit_sha)]:
            del scan_cache[abs_repo_path][str(commit_sha)]["checkout_error"]
    
    sha_cache = scan_cache.get(abs_repo_path, {}).get(str(commit_sha), {})

    if not sha_cache.get("checkout_error"):
        code_scan_status = sha_cache.get("code_scanned_successfully")
        if code_scan_status is None or not code_scan_status:
            print(f"⚙️  Scan Snyk CODE pour {output_repo_name_cleaned}...")
            snyk_code_success = safe_run_snyk_command(["code", "test", "--json"], code_output, cwd=abs_repo_path)
            scan_cache[abs_repo_path][str(commit_sha)]["code_scanned_successfully"] = snyk_code_success
            if not snyk_code_success: print(f"    ⚠️  Échec Snyk Code pour {output_repo_name_cleaned}@{short_sha}. Voir {code_output}")

        sha_cache = scan_cache.get(abs_repo_path, {}).get(str(commit_sha), {}) # Recharger pour l'état du scan de code
        iac_scan_status = sha_cache.get("iac_scanned_successfully")
        if iac_scan_status is None or not iac_scan_status:
            print(f"⚙️  Scan Snyk IaC pour {output_repo_name_cleaned}...")
            snyk_iac_success = safe_run_snyk_command(["iac", "test", "--json"], iac_output, cwd=abs_repo_path)
            scan_cache[abs_repo_path][str(commit_sha)]["iac_scanned_successfully"] = snyk_iac_success
            if not snyk_iac_success: print(f"    ⚠️  Échec Snyk IaC pour {output_repo_name_cleaned}@{short_sha}. Voir {iac_output}")
    else:
        print(f"    Scan Snyk ignoré pour {output_repo_name_cleaned}@{short_sha} en raison d'une erreur de checkout.")


# === EXECUTION ===
if __name__ == "__main__":
    if not GIT_PATH:
        print("Le script ne peut pas continuer sans trouver l'exécutable git.")
        sys.exit(1)
    if not SNYK_PATH:
        print("Le script ne peut pas continuer sans trouver l'exécutable snyk.")
        sys.exit(1)
        
    print("INFO: Ce script est destiné à être exécuté avec les permissions nécessaires (ex: root).")
    print("      Assurez-vous que Snyk est authentifié pour l'utilisateur effectif (ex: `sudo snyk auth`).")
    current_user_is_root = False
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        current_user_is_root = True
        print("      Le script est bien exécuté en tant que root.")
    else:
        print("      Avertissement: Le script n'est pas exécuté en tant que root. Des erreurs de permission peuvent survenir.")


    try:
        df = pd.read_excel(EXCEL_FILE)
    except FileNotFoundError:
        print(f"❌ ERREUR CRITIQUE : Le fichier Excel '{EXCEL_FILE}' n'a pas été trouvé.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ ERREUR CRITIQUE lors de la lecture du fichier Excel '{EXCEL_FILE}': {e}")
        sys.exit(1)
        
    if REPO_FOLDER_NAME_COLUMN not in df.columns or COMMIT_SHA_COLUMN not in df.columns:
        print(f"❌ Colonnes '{REPO_FOLDER_NAME_COLUMN}' et/ou '{COMMIT_SHA_COLUMN}' manquantes dans l'Excel.")
        print(f"   Colonnes disponibles: {df.columns.tolist()}")
        sys.exit(1)

    total = len(df)
    for i, row in df.iterrows():
        repo_folder = row[REPO_FOLDER_NAME_COLUMN]
        sha = row[COMMIT_SHA_COLUMN]
        
        if pd.isna(repo_folder) or pd.isna(sha) or not str(repo_folder).strip() or not str(sha).strip():
            print(f"\n🟦 [{i+1}/{total}] Ligne ignorée : Nom du dossier ou SHA manquant/invalide.")
            continue
            
        repo_folder_str = str(repo_folder).strip()
        sha_str = str(sha).strip()
        
        print(f"\n🟦 [{i+1}/{total}] Dossier Dépôt : {repo_folder_str} | Commit : {sha_str}")
        run_snyk_scan_on_commit(repo_folder_str, sha_str)
        save_scan_cache(scan_cache)

    print("\n✅ Tous les scans (ou tentatives de scan) terminés.")