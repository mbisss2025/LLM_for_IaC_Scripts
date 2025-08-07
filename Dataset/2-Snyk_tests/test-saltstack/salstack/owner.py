import os
import subprocess
import re
# import pandas as pd # Sera nécessaire si vous décommentez la partie sauvegarde Excel

def get_git_repo_owner_and_name(repo_path):
    """
    Exécute 'git remote -v' dans le chemin du dépôt et extrait l'owner/repo.
    Ajoute le répertoire à safe.directory avant.

    Args:
        repo_path (str): Le chemin d'accès au dépôt Git local.

    Returns:
        tuple: (owner, repo_name) ou (None, None) si non trouvé ou erreur.
    """
    abs_repo_path = os.path.abspath(repo_path) # Utiliser le chemin absolu

    try:
        # Ajouter le répertoire à la configuration globale safe.directory de Git
        # Cela permet d'éviter les erreurs liées à la propriété du dépôt.
        print(f"    Ajout de '{abs_repo_path}' à safe.directory (global)...")
        config_command = ["git", "config", "--global", "--add", "safe.directory", abs_repo_path]
        config_result = subprocess.run(
            config_command,
            capture_output=True,
            text=True,
            check=False, # Ne pas lever d'exception si la commande échoue (ex: déjà ajouté)
            encoding='utf-8',
            errors='ignore'
        )
        if config_result.returncode != 0:
            # Un code de sortie non nul n'est pas toujours une erreur critique ici
            # (ex: le répertoire est déjà listé, ou la version de Git est très ancienne)
            # On affiche un avertissement mais on continue.
            print(f"    Avertissement lors de l'exécution de '{' '.join(config_command)}': {config_result.stderr.strip()}")
        else:
            print(f"    '{abs_repo_path}' ajouté/confirmé dans safe.directory.")

        # Exécuter la commande git remote -v
        print(f"    Exécution de 'git remote -v' dans '{abs_repo_path}'...")
        result = subprocess.run(
            ["git", "remote", "-v"],
            cwd=abs_repo_path,  # Utiliser le chemin absolu pour cwd aussi
            capture_output=True,
            text=True,
            check=True, 
            encoding='utf-8',
            errors='ignore'
        )
        
        output_lines = result.stdout.strip().split('\n')
        
        for line in output_lines:
            if "(fetch)" in line.lower(): # Rendre la recherche de (fetch) insensible à la casse
                parts = line.split()
                if len(parts) >= 2:
                    url = parts[1]
                    
                    ssh_match = re.search(r'git@[\w.-]+:([\w.-]+)/([\w.-]+?)(?:\.git)?$', url)
                    if ssh_match:
                        owner = ssh_match.group(1)
                        repo_name = ssh_match.group(2)
                        return owner, repo_name
                    
                    https_match = re.search(r'https://[\w.-]+/([\w.-]+)/([\w.-]+?)(?:\.git)?$', url)
                    if https_match:
                        owner = https_match.group(1)
                        repo_name = https_match.group(2)
                        return owner, repo_name
                        
        print(f"    Impossible d'analyser l'URL de 'fetch' pour {abs_repo_path} à partir de la sortie :\n{result.stdout}")
        return None, None

    except subprocess.CalledProcessError as e:
        # Si 'git remote -v' échoue (par exemple, pas un dépôt git après tout, ou remote non configuré)
        error_output = e.stderr.strip() if e.stderr else e.stdout.strip() if e.stdout else "Erreur inconnue"
        print(f"    Erreur lors de l'exécution de 'git remote -v' dans {abs_repo_path}: {error_output}")
        return None, None
    except FileNotFoundError:
        print(f"    Erreur : La commande 'git' n'a pas été trouvée. Assurez-vous que Git est installé et dans le PATH.")
        return None, None # Retourner pour éviter de crasher le script principal
    except Exception as e:
        print(f"    Une erreur inattendue s'est produite pour {abs_repo_path}: {e}")
        return None, None

# Le reste du script (find_git_repos_and_owners, Configuration, if __name__ == "__main__")
# reste identique à la version précédente. Assurez-vous de l'inclure si vous recréez le fichier.

# Exemple de la fonction find_git_repos_and_owners et du bloc main (à inclure) :
def find_git_repos_and_owners(base_directory):
    """
    Parcourt les sous-répertoires, identifie les dépôts Git et leurs propriétaires/noms.
    """
    print(f"Recherche des dépôts Git et de leurs propriétaires dans : {os.path.abspath(base_directory)}\n")
    
    found_repos_info = []

    for item_name in os.listdir(base_directory):
        item_path = os.path.join(base_directory, item_name)
        
        if os.path.isdir(item_path) and os.path.isdir(os.path.join(item_path, ".git")):
            print(f"ℹ️  Dépôt Git trouvé : {item_name}")
            owner, repo_name = get_git_repo_owner_and_name(item_path) # item_path est déjà un chemin
            if owner and repo_name:
                print(f"    Propriétaire/Organisation : {owner}, Nom du dépôt : {repo_name}")
                found_repos_info.append({
                    "dossier_local": item_name,
                    "chemin_complet": os.path.abspath(item_path),
                    "proprietaire": owner,
                    "nom_depot_distant": repo_name
                })
            else:
                print(f"    Impossible de déterminer le propriétaire/nom du dépôt distant pour {item_name}.")
                found_repos_info.append({
                    "dossier_local": item_name,
                    "chemin_complet": os.path.abspath(item_path),
                    "proprietaire": "Inconnu",
                    "nom_depot_distant": "Inconnu"
                })
        elif os.path.isdir(item_path):
            print(f"  (Ignoré) '{item_name}' est un dossier mais n'est pas un dépôt Git.")

    if not found_repos_info:
        print("\nℹ️ Aucun dépôt Git n'a été trouvé dans les sous-dossiers directs.")
    else:
        try:
            import pandas as pd # Importation de pandas ici pour la sauvegarde
            df_repos = pd.DataFrame(found_repos_info)
            output_file = "proprietaires_depots_locaux.xlsx" # Nom du fichier de sortie
            df_repos.to_excel(output_file, index=False)
            print(f"\n✅ Les informations des dépôts trouvés ont été sauvegardées dans '{output_file}'")
        except ImportError:
            print("\n(Note : La bibliothèque pandas n'est pas installée. Les résultats ne sont pas sauvegardés dans un fichier Excel.)")
        except Exception as e:
            print(f"\nErreur lors de la sauvegarde des résultats dans Excel : {e}")


# --- Configuration ---
BASE_DIRECTORY_TO_SCAN = "." 
# Exemple pour WSL : BASE_DIRECTORY_TO_SCAN = "/home/mbissine/gitclone_saltstack"
# --------------------

if __name__ == "__main__":
    find_git_repos_and_owners(BASE_DIRECTORY_TO_SCAN)