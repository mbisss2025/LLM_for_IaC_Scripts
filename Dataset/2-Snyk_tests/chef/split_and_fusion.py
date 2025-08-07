import pandas as pd
import re
import os

def parse_snyk_filename_for_keys(filename_series):
    """
    Extrait 'nom_derived' et 'debut_sha_derived' à partir d'une série de noms de fichiers Snyk.
    Ces clés seront utilisées pour la jointure.

    Args:
        filename_series (pd.Series): Une série Pandas de noms de fichiers.

    Returns:
        pd.DataFrame: Un DataFrame avec les colonnes 'nom_derived' et 'debut_sha_derived'.
    """
    results = []
    # Pattern: snyk-code-(NOM_ET_ANNEE)-(DEBUT_SHA).json
    pattern = re.compile(r"snyk-code-(.+)-([a-zA-Z0-9]{7,})\.json$")

    for filename in filename_series:
        nom = None
        debut_sha = None
        if isinstance(filename, str):
            match = pattern.match(filename)
            if match:
                nom = match.group(1)
                debut_sha = match.group(2)
            else: # Logique de secours
                try:
                    if filename.startswith("snyk-code-") and filename.endswith(".json"):
                        base_name = filename[len("snyk-code-"):-len(".json")]
                        parts = base_name.rsplit('-', 1)
                        if len(parts) == 2:
                            if re.fullmatch(r"[0-9a-fA-F]{6,12}", parts[1]):
                                nom = parts[0]
                                debut_sha = parts[1]
                            else:
                                nom = base_name
                        else:
                            nom = base_name
                except Exception:
                    pass # Laisser nom et debut_sha à None
        results.append({'nom_derived': nom, 'debut_sha_derived': debut_sha})
    return pd.DataFrame(results)

def create_enriched_snyk_report(
    snyk_results_path,
    original_filename_col_in_snyk_results,
    references_shas_path,
    sha_col_in_references,
    repo_name_col_in_references,
    output_path="snyk_code_results_enriched.xlsx"
):
    """
    Combine les informations de snyk_code_results.xlsx et d'un fichier de références SHA
    pour produire un rapport Snyk Code enrichi avec nom_repo et commit_sha.

    Args:
        snyk_results_path (str): Chemin vers le fichier snyk_code_results.xlsx.
        original_filename_col_in_snyk_results (str): Nom de la colonne dans snyk_results_path
                                                     contenant les noms de fichiers JSON originaux.
        references_shas_path (str): Chemin vers le fichier Excel contenant les SHAs complets
                                    et les noms de dépôt de référence.
        sha_col_in_references (str): Nom de la colonne SHA dans references_shas_path.
        repo_name_col_in_references (str): Nom de la colonne contenant le nom du dépôt GitHub
                                           dans references_shas_path.
        output_path (str, optional): Chemin pour le fichier Excel enrichi final.
    """
    # --- Étape 1 & 2 (combinées) : Lire snyk_code_results.xlsx et préparer les clés de jointure ---
    try:
        df_snyk = pd.read_excel(snyk_results_path)
        print(f"Fichier '{snyk_results_path}' lu avec succès.")
    except FileNotFoundError:
        print(f"Erreur : Le fichier '{snyk_results_path}' n'a pas été trouvé.")
        return
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier '{snyk_results_path}': {e}")
        return

    if original_filename_col_in_snyk_results not in df_snyk.columns:
        print(f"Erreur : La colonne '{original_filename_col_in_snyk_results}' est manquante dans '{snyk_results_path}'.")
        print(f"Colonnes disponibles : {df_snyk.columns.tolist()}")
        return

    # Extraire 'nom_derived' et 'debut_sha_derived' à partir de la colonne des noms de fichiers
    df_snyk_join_keys = parse_snyk_filename_for_keys(df_snyk[original_filename_col_in_snyk_results])
    # Concaténer ces clés dérivées au DataFrame original
    # S'assurer que les index sont alignés pour une concaténation correcte
    df_snyk_with_keys = pd.concat([df_snyk.reset_index(drop=True), df_snyk_join_keys.reset_index(drop=True)], axis=1)
    print("Clés 'nom_derived' et 'debut_sha_derived' créées pour le fichier Snyk.")


    # --- Étape 3 : Lire le fichier de références SHA et préparer les données pour la recherche ---
    try:
        df_references = pd.read_excel(references_shas_path)
        print(f"Fichier de références '{references_shas_path}' lu avec succès.")
    except FileNotFoundError:
        print(f"Erreur : Le fichier de références '{references_shas_path}' n'a pas été trouvé.")
        return
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier de références '{references_shas_path}': {e}")
        return

    # Vérification des colonnes nécessaires dans df_references
    if sha_col_in_references not in df_references.columns:
        print(f"Erreur : La colonne '{sha_col_in_references}' est manquante dans '{references_shas_path}'.")
        return
    if repo_name_col_in_references not in df_references.columns:
        print(f"Erreur : La colonne '{repo_name_col_in_references}' est manquante dans '{references_shas_path}'.")
        return

    # Préparer les colonnes de df_references pour la recherche
    df_references['sha_str_ref'] = df_references[sha_col_in_references].astype(str).str.lower().str.strip()
    # S'assurer que la colonne repo_name est aussi une chaîne pour éviter les erreurs de type plus tard
    df_references['repo_name_str_ref'] = df_references[repo_name_col_in_references].astype(str)


    # Créer une liste de dictionnaires pour une recherche plus codeile des SHAs et noms de repo
    reference_lookup = []
    for index, row in df_references.iterrows():
        full_sha = row['sha_str_ref']
        repo_name = row['repo_name_str_ref']
        if full_sha != 'nan' and pd.notna(full_sha) and full_sha: # Ignorer les NaN ou vides
            reference_lookup.append({'full_sha': full_sha, 'repo_name': repo_name})
    print(f"{len(reference_lookup)} entrées de référence chargées pour la recherche SHA.")


    # --- Étape 4 : Faire correspondre et enrichir df_snyk_with_keys ---
    nom_repo_list = []
    commit_sha_list = []

    # Convertir debut_sha_derived en chaîne pour la comparaison
    df_snyk_with_keys['debut_sha_derived_str'] = df_snyk_with_keys['debut_sha_derived'].astype(str).str.lower().str.strip()

    for index, snyk_row in df_snyk_with_keys.iterrows():
        current_debut_sha = snyk_row['debut_sha_derived_str']
        found_repo_name = pd.NA
        found_commit_sha = pd.NA

        if current_debut_sha != 'nan' and pd.notna(current_debut_sha) and current_debut_sha:
            for ref_entry in reference_lookup:
                if ref_entry['full_sha'].startswith(current_debut_sha):
                    found_repo_name = ref_entry['repo_name']
                    found_commit_sha = ref_entry['full_sha']
                    break # Prendre la première correspondance
        
        nom_repo_list.append(found_repo_name)
        commit_sha_list.append(found_commit_sha)

    df_snyk_with_keys['nom_repo'] = nom_repo_list
    df_snyk_with_keys['commit_sha'] = commit_sha_list
    print("Colonnes 'nom_repo' et 'commit_sha' peuplées.")

    # --- Étape 5 : Nettoyage et sauvegarde ---
    # Supprimer les colonnes de jointure/travail temporaires
    cols_to_drop_final = ['nom_derived', 'debut_sha_derived', 'debut_sha_derived_str']
    df_final_report = df_snyk_with_keys.drop(columns=[col for col in cols_to_drop_final if col in df_snyk_with_keys.columns])


    try:
        df_final_report.to_excel(output_path, index=False)
        print(f"Rapport Snyk Code enrichi sauvegardé avec succès sous '{output_path}'.")
    except Exception as e:
        print(f"Erreur lors de l'écriture du fichier de sortie '{output_path}': {e}")


# --- Configuration Principale ---
# REMPcodeEZ CES VALEURS PAR VOS NOMS DE FICHIERS ET DE COLONNES

# Fichier Snyk Code original (sortie du tout premier script JSON -> Excel)
SNYK_RESULTS_INPUT_PATH = r"C:\\Users\\DELL\\Documents\\test_snyk\\Test5-chef\\snykanalyse\\snyk_code_results.xlsx"
# Nom de la colonne dans SNYK_RESULTS_INPUT_PATH qui contient les noms de fichiers JSON sources
# (ex: "snyk-code-projetX-abcdef1.json")
ORIGINAL_FILENAME_COLUMN_IN_SNYK_RESULTS = "original_filename"

# Fichier Excel contenant les SHAs complets et les noms de dépôt GitHub correspondants
REFERENCES_SHAS_INPUT_PATH = r"C:\\Users\\DELL\\Documents\\test_snyk\\Test5-chef\\snykanalyse\\dataset_chef_avec_repos.xlsx"
# Nom de la colonne SHA complet dans REFERENCES_SHAS_INPUT_PATH
SHA_COLUMN_IN_REFERENCES = "commit_sha"
# Nom de la colonne contenant les noms de dépôt GitHub dans REFERENCES_SHAS_INPUT_PATH
REPO_NAME_COLUMN_IN_REFERENCES = "repo_github"

# Fichier Excel de sortie final
OUTPUT_ENRICHED_FILE_PATH = "snyk_code_results_enriched.xlsx"
# ------------------------------------

if __name__ == "__main__":
    create_enriched_snyk_report(
        SNYK_RESULTS_INPUT_PATH,
        ORIGINAL_FILENAME_COLUMN_IN_SNYK_RESULTS,
        REFERENCES_SHAS_INPUT_PATH,
        SHA_COLUMN_IN_REFERENCES,
        REPO_NAME_COLUMN_IN_REFERENCES,
        OUTPUT_ENRICHED_FILE_PATH
    )