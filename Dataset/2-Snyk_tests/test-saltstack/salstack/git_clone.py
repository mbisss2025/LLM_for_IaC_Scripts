import pandas as pd
import subprocess
import os

# --- Configuration ---
# Modifiez ces valeurs selon vos besoins
EXCEL_FILE_PATH = "salt.xlsx"  # Remplacez par le chemin de votre fichier Excel
REPO_COLUMN_NAME = "repo_github"       # Nom de la colonne contenant les URL des dépôts GitHub
CLONE_DESTINATION_DIR = "" # Optionnel: Répertoire où cloner les dépôts.
                                        # Laissez vide ("") pour cloner dans le répertoire courant du script.
                                        # Si spécifié, le répertoire sera créé s'il n'existe pas.

# --- Fonctions Utilitaires ---
def get_repo_name_from_url(url):
    """Extrait le nom du dépôt à partir de l'URL."""
    try:
        repo_name = url.split('/')[-1]
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]
        return repo_name
    except Exception:
        return None

# --- Script Principal ---
def main():
    print("--- Début du script de clonage des dépôts GitHub ---")

    # 1. Vérifier si le fichier Excel existe
    if not os.path.exists(EXCEL_FILE_PATH):
        print(f"ERREUR : Le fichier Excel '{EXCEL_FILE_PATH}' n'a pas été trouvé.")
        print("Veuillez vérifier le chemin et le nom du fichier dans la variable 'EXCEL_FILE_PATH'.")
        return

    # 2. Créer le répertoire de destination s'il est spécifié et n'existe pas
    clone_base_path_for_repos = os.getcwd() # Par défaut, le répertoire courant du script
    if CLONE_DESTINATION_DIR:
        # Si CLONE_DESTINATION_DIR est un chemin absolu, il sera utilisé tel quel.
        # S'il est relatif, il sera relatif au répertoire courant du script.
        abs_clone_destination_dir = os.path.abspath(CLONE_DESTINATION_DIR)
        if not os.path.exists(abs_clone_destination_dir):
            try:
                os.makedirs(abs_clone_destination_dir)
                print(f"INFO : Répertoire de destination '{abs_clone_destination_dir}' créé.")
            except OSError as e:
                print(f"ERREUR : Impossible de créer le répertoire de destination '{abs_clone_destination_dir}': {e}")
                return
        clone_base_path_for_repos = abs_clone_destination_dir
        print(f"INFO : Les dépôts seront clonés dans le répertoire : '{clone_base_path_for_repos}'")
    else:
        print(f"INFO : Les dépôts seront clonés dans le répertoire courant du script : '{clone_base_path_for_repos}'")

    # 3. Lire le fichier Excel
    try:
        df = pd.read_excel(EXCEL_FILE_PATH)
        print(f"INFO : Fichier Excel '{EXCEL_FILE_PATH}' lu avec succès.")
    except FileNotFoundError:
        print(f"ERREUR : Le fichier Excel '{EXCEL_FILE_PATH}' n'a pas été trouvé.")
        return
    except Exception as e:
        print(f"ERREUR : Une erreur s'est produite lors de la lecture du fichier Excel : {e}")
        return

    # 4. Vérifier si la colonne des dépôts existe
    if REPO_COLUMN_NAME not in df.columns:
        print(f"ERREUR : La colonne '{REPO_COLUMN_NAME}' n'a pas été trouvée dans le fichier Excel.")
        print(f"Colonnes disponibles : {', '.join(df.columns)}")
        print("Veuillez vérifier le nom de la colonne dans la variable 'REPO_COLUMN_NAME'.")
        return

    # 5. Itérer sur chaque ligne et cloner le dépôt
    for index, row in df.iterrows():
        repo_url = row[REPO_COLUMN_NAME]

        if pd.isna(repo_url) or not isinstance(repo_url, str) or not repo_url.strip():
            print(f"\nAVERTISSEMENT : Ligne {index + 2} : URL du dépôt manquante, vide ou invalide. Ignoré.")
            continue

        repo_url = repo_url.strip()
        print(f"\n--- Traitement de la ligne {index + 2} : Dépôt '{repo_url}' ---")

        repo_name = get_repo_name_from_url(repo_url)
        if not repo_name:
            print(f"ERREUR : Impossible d'extraire le nom du dépôt depuis l'URL '{repo_url}'. Ignoré.")
            continue
        
        destination_repo_path = os.path.join(clone_base_path_for_repos, repo_name)

        if os.path.exists(destination_repo_path):
            print(f"INFO : Le répertoire '{destination_repo_path}' existe déjà. Le clonage est ignoré pour ce dépôt.")
            continue

        # La commande git clone sera `git clone <url_repo> <nom_repo_local>`
        # Elle sera exécutée dans `clone_base_path_for_repos`.
        command_to_run = ["git", "clone", repo_url, repo_name]

        try:
            print(f"INFO : Tentative de clonage de '{repo_url}'")
            print(f"Destination : '{destination_repo_path}'")
            print(f"La progression du clonage pour '{repo_name}' s'affichera ci-dessous:")
            
            # Exécuter la commande. La sortie de git (progression, erreurs) ira directement à la console.
            process = subprocess.run(
                command_to_run,
                cwd=clone_base_path_for_repos, # Le clonage se fera dans ce répertoire de base
                check=False  # Important: ne pas lever d'exception pour les codes de retour non nuls
                             # car nous voulons gérer l'erreur nous-mêmes.
                # Pas de 'capture_output=True' pour que la sortie aille à la console.
                # Pas de 'text=True' car nous ne capturons pas la sortie pour la décoder.
            )

            if process.returncode == 0:
                print(f"\nSUCCÈS : Dépôt '{repo_name}' cloné avec succès dans '{destination_repo_path}'.")
            else:
                # Les messages d'erreur de Git auront déjà été affichés sur la console.
                print(f"\nERREUR : Échec du clonage du dépôt '{repo_url}'.")
                print(f"Code de retour Git : {process.returncode}")
                print("Veuillez consulter les messages de Git affichés ci-dessus pour plus de détails.")

        except FileNotFoundError:
            print("ERREUR CRITIQUE : La commande 'git' n'a pas été trouvée.")
            print("Assurez-vous que Git est installé et configuré correctement dans le PATH de votre système.")
            print("Arrêt du script.")
            return # Arrête tout le script si git n'est pas trouvé
        except Exception as e:
            print(f"ERREUR INATTENDUE : Une erreur s'est produite lors du clonage de '{repo_url}': {e}")

    print("\n--- Fin du script de clonage ---")

if __name__ == "__main__":
    main()
