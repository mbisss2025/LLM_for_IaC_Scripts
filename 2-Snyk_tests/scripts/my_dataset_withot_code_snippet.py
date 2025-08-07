import pandas as pd
import numpy as np # Pour pd.NA

def create_structured_analysis_report_v2( # Renommé pour indiquer une nouvelle version
    enriched_input_path,
    output_path
):
    """
    Génère un fichier Excel structuré à partir du fichier snyk_code_results_enriched.xlsx.
    Utilise la colonne 'nom_repo' (qui est une URL complète de dépôt) pour construire 'commit_url'.

    Args:
        enriched_input_path (str): Chemin vers le fichier snyk_code_results_enriched.xlsx.
        output_path (str): Chemin pour sauvegarder le nouveau fichier Excel structuré.
    """
    try:
        df_enriched = pd.read_excel(enriched_input_path)
        print(f"Fichier d'entrée '{enriched_input_path}' lu avec succès.")
    except FileNotFoundError:
        print(f"Erreur : Le fichier d'entrée '{enriched_input_path}' n'a pas été trouvé.")
        return
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier Excel d'entrée '{enriched_input_path}': {e}")
        return

    print(f"Colonnes disponibles dans le fichier d'entrée : {df_enriched.columns.tolist()}")

    df_output = pd.DataFrame()

    # 1. vulnerability (depuis 'rule_short_description')
    vulnerability_source_col = 'rule_short_description'
    if vulnerability_source_col in df_enriched.columns:
        df_output['vulnerability'] = df_enriched[vulnerability_source_col]
    else:
        print(f"Attention : Colonne '{vulnerability_source_col}' non trouvée. La colonne 'vulnerability' sera vide.")
        df_output['vulnerability'] = pd.NA

    # 2. filepath (depuis 'location_uri')
    filepath_source_col = 'location_uri'
    if filepath_source_col in df_enriched.columns:
        df_output['filepath'] = df_enriched[filepath_source_col]
    else:
        print(f"Attention : Colonne '{filepath_source_col}' non trouvée. La colonne 'filepath' sera vide.")
        df_output['filepath'] = pd.NA

    # 3. line (logique conditionnelle)
    start_line_col = 'location_start_line'
    end_line_col = 'location_end_line'
    if start_line_col in df_enriched.columns and end_line_col in df_enriched.columns:
        lines = []
        for index, row in df_enriched.iterrows():
            start = row[start_line_col]
            end = row[end_line_col]
            if pd.isna(start) or pd.isna(end):
                lines.append(pd.NA)
            elif start != end:
                lines.append(f"({int(start)}, {int(end)})") # S'assurer que ce sont des entiers avant la conversion
            else:
                lines.append(int(start) if pd.notna(start) else pd.NA) # Gérer NaN pour start aussi
        df_output['line'] = lines
    else:
        print(f"Attention : Colonnes '{start_line_col}' et/ou '{end_line_col}' non trouvées. La colonne 'line' sera vide.")
        df_output['line'] = pd.NA

    # 4. location_start_column
    start_col_col = 'location_start_column'
    if start_col_col in df_enriched.columns:
        df_output['location_start_column'] = df_enriched[start_col_col]
    else:
        print(f"Attention : Colonne '{start_col_col}' non trouvée. La colonne 'location_start_column' sera vide.")
        df_output['location_start_column'] = pd.NA

    # 5. location_end_column
    end_col_col = 'location_end_column'
    if end_col_col in df_enriched.columns:
        df_output['location_end_column'] = df_enriched[end_col_col]
    else:
        print(f"Attention : Colonne '{end_col_col}' non trouvée. La colonne 'location_end_column' sera vide.")
        df_output['location_end_column'] = pd.NA

    # 6. commit_url (construit à partir de nom_repo https://www.merriam-webster.com/dictionary/complete et commit_sha)
    nom_repo_col = 'nom_repo' # Contient maintenant l'URL complète du dépôt
    commit_sha_col = 'commit_sha'
    commit_urls = []
    if nom_repo_col in df_enriched.columns and commit_sha_col in df_enriched.columns:
        for index, row in df_enriched.iterrows():
            repo_full_url = row[nom_repo_col]
            sha = row[commit_sha_col]
            
            # Vérifier que repo_full_url et sha ne sont pas NaN et sont des chaînes non vides
            if pd.notna(repo_full_url) and isinstance(repo_full_url, str) and repo_full_url.strip() and \
               pd.notna(sha) and isinstance(sha, str) and sha.strip():
                
                # S'assurer que l'URL du dépôt ne se termine pas par un slash
                # avant d'ajouter "/commit/"
                cleaned_repo_url = repo_full_url.strip()
                if cleaned_repo_url.endswith('/'):
                    cleaned_repo_url = cleaned_repo_url[:-1]
                commit_urls.append(f"{cleaned_repo_url}/commit/{sha.strip()}")
            else:
                commit_urls.append(pd.NA) # Mettre pd.NA si les infos sont manquantes
        df_output['commit_url'] = commit_urls
    else:
        missing_cols = []
        if nom_repo_col not in df_enriched.columns:
            missing_cols.append(nom_repo_col)
        if commit_sha_col not in df_enriched.columns:
            missing_cols.append(commit_sha_col)
        print(f"Attention : Colonne(s) {', '.join(missing_cols)} non trouvée(s). La colonne 'commit_url' sera vide.")
        df_output['commit_url'] = pd.NA

    # 7. previous_code (placeholder)
    df_output['previous_code'] = "" 

    # 8. after_code (placeholder)
    df_output['after_code'] = "" 
    
    # Assurer l'ordre des colonnes
    final_column_order = [
        'vulnerability',
        'commit_url',
        'filepath',
        'line',
        'location_start_column',
        'location_end_column',
        'previous_code',
        'after_code'
    ]
    # Optionnel : Si vous voulez aussi inclure nom_repo et commit_sha dans ce fichier final pour référence
    # Décommentez et ajustez la section suivante :
    # for col_to_carry_over in ['nom_repo', 'commit_sha']:
    #     if col_to_carry_over in df_enriched.columns and col_to_carry_over not in final_column_order:
    #         final_column_order.append(col_to_carry_over) # Ajoute à la fin de la liste
    #         df_output[col_to_carry_over] = df_enriched[col_to_carry_over]


    df_output = df_output.reindex(columns=final_column_order)

    try:
        df_output.to_excel(output_path, index=False, sheet_name='Structured Analysis V2')
        print(f"Rapport structuré V2 sauvegardé avec succès sous '{output_path}'")
        print("\n--- Informations importantes concernant le fichier généré ---")
        print("Les colonnes 'previous_code' et 'after_code' sont des placeholders.")
        print("La colonne 'commit_url' a été construite en utilisant la colonne 'nom_repo' (comme URL de base du dépôt) et 'commit_sha'.")
    except Exception as e:
        print(f"Erreur lors de l'écriture du fichier de sortie '{output_path}': {e}")

# --- Configuration ---
# REMPLACEZ CES VALEURS SI NÉCESSAIRE

# Fichier d'entrée (celui qui contient déjà nom_repo https://www.merriam-webster.com/dictionary/complete et commit_sha)
ENRICHED_INPUT_FILE_PATH_V2 = r"C:\\Users\\DELL\\Documents\\test_snyk\\test6-pulumi\\snykanalyse\\pulumi_snyk_code_results_enriched.xlsx"  # ou "corr_final_report.xlsx" de l'étape précédente

# Fichier Excel de sortie final avec la structure demandée
STRUCTURED_OUTPUT_FILE_PATH_V2 = r"C:\\Users\\DELL\\Documents\\test_snyk\\test6-pulumi\\snykanalyse\\snyk_code_pulumi_corrected_without.xlsx"

# La variable GITHUB_BASE_URL n'est plus nécessaire ici si nom_repo est une URL complète.
# --------------------

if __name__ == "__main__":
    create_structured_analysis_report_v2(
        ENRICHED_INPUT_FILE_PATH_V2,
        STRUCTURED_OUTPUT_FILE_PATH_V2
    )