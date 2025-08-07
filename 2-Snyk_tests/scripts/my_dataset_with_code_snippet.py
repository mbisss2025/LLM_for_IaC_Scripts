import json
import pandas as pd
import requests
import base64
import re
import os
from urllib.parse import urlparse

# --- Configuration ---
# Token GitHub (TRÈS IMPORTANT)
# REMPLACEZ "VOTRE_TOKEN_ICI" par votre véritable token ou lisez-le depuis une variable d'environnement.
# Par sécurité, il est préférable de ne PAS coder en dur le token dans le script.
# Exemple avec variable d'environnement:
# GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
GITHUB_TOKEN = "YOUR_GITHUB_TOKEN" # L'utilisateur a fourni son token ici


HEADERS = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json',
}

# Nombre de lignes de contexte si 'line' est un seul numéro
CONTEXT_LINES_FOR_SINGLE_LINE = 2

# --- Fonctions Utilitaires ---

def parse_github_commit_url(url_str):
    if not isinstance(url_str, str):
        return None, None, None
    try:
        # S'assurer que l'URL a un schéma
        if not url_str.startswith(('http://', 'https://')):
            url_str = 'https://' + url_str # Supposer https par défaut
        
        parsed_url = urlparse(url_str)
        path_parts = parsed_url.path.strip('/').split('/')
        
        if len(path_parts) >= 4 and path_parts[2].lower().startswith('commit'):
            owner = path_parts[0]
            repo = path_parts[1]
            sha = path_parts[3]
            return owner, repo, sha
    except Exception as e:
        print(f"Erreur lors de l'analyse de l'URL '{url_str}': {e}")
    return None, None, None

def get_file_content_at_commit(owner, repo, filepath, sha):
    if not all([owner, repo, filepath, sha]):
        return None, f"Paramètres manquants pour l'API : owner={owner}, repo={repo}, path={filepath}, sha={sha}"
    
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filepath}?ref={sha}"
    try:
        response = requests.get(api_url, headers=HEADERS, timeout=20)
        response.raise_for_status()
        data = response.json() # Stocker la réponse JSON
        content_base64 = data.get('content')
        if content_base64:
            return base64.b64decode(content_base64).decode('utf-8'), None
        else:
            file_type = data.get('type')
            if file_type == 'dir':
                return None, f"Le chemin '{filepath}' est un répertoire, pas un fichier."
            # Si 'content' est manquant mais que ce n'est pas un dossier, et pas d'erreur HTTP, c'est étrange
            return None, "Contenu non trouvé dans la réponse JSON (champ 'content' manquant ou vide)."
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            return None, f"Fichier non trouvé (404) : {filepath} au commit {sha} dans {owner}/{repo}."
        elif response.status_code == 403:
             try: # Essayer de parser le message d'erreur JSON de GitHub
                error_details = response.json().get('message', str(http_err))
                if "too large" in error_details.lower():
                     return None, f"Fichier trop volumineux (403) : {filepath}. API Contents limitée à 1Mo. Erreur: {error_details}"
                else:
                    return None, f"Erreur HTTP 403 (Forbidden) : {filepath} au commit {sha}. Vérifiez les permissions du token ou les limites de l'API. Détails: {error_details}"
             except json.JSONDecodeError: # Si la réponse d'erreur n'est pas JSON
                return None, f"Erreur HTTP 403 (Forbidden) : {filepath} au commit {sha}. Réponse non-JSON: {response.text}"
        return None, f"Erreur HTTP lors de la récupération du fichier : {http_err} pour {api_url}"
    except requests.exceptions.Timeout:
        return None, f"Timeout lors de la récupération du fichier {filepath} à {sha} pour {api_url}"
    except json.JSONDecodeError: # Si la réponse initiale n'est pas un JSON valide (avant même de chercher 'content')
        return None, f"Réponse non-JSON de l'API pour {filepath} à {sha} pour {api_url}. Contenu: {response.text[:200]}"
    except Exception as e:
        return None, f"Erreur lors de la récupération du contenu du fichier {filepath} à {sha}: {e} pour {api_url}"

def parse_line_input(line_val_from_excel):
    if pd.isna(line_val_from_excel):
        return None, None, None
    if isinstance(line_val_from_excel, (int, float)):
        num_line = int(line_val_from_excel)
        return 'single', num_line, num_line
    if isinstance(line_val_from_excel, str):
        match_tuple = re.match(r'\((\d+),\s*(\d+)\)', line_val_from_excel)
        if match_tuple:
            start_r, end_r = int(match_tuple.group(1)), int(match_tuple.group(2))
            if start_r > end_r: 
                 start_r, end_r = end_r, start_r
            return 'range', start_r, end_r
        try:
            num_line = int(line_val_from_excel)
            return 'single', num_line, num_line
        except ValueError:
            return None, None, None
    return None, None, None

def extract_code_block_by_range(file_content, block_start_1idx, block_end_1idx):
    if file_content is None:
        return "Erreur: Contenu du fichier non disponible."
    
    lines = file_content.splitlines()
    num_total_lines = len(lines)

    actual_start_0idx = max(0, block_start_1idx - 1)
    actual_end_0idx = min(num_total_lines - 1, block_end_1idx - 1)

    if actual_start_0idx > actual_end_0idx : 
        return f"Erreur: Plage de lignes calculée invalide ({block_start_1idx}-{block_end_1idx}) pour un fichier de {num_total_lines} lignes."
        
    block_lines = lines[actual_start_0idx : actual_end_0idx + 1]
    return "\n".join(block_lines)


def process_file_content_for_snippets_v3(input_excel_path, output_excel_path, num_rows_to_process=None):
    try:
        df_full = pd.read_excel(input_excel_path)
        print(f"Fichier d'entrée '{input_excel_path}' lu avec succès ({len(df_full)} lignes).")
    except FileNotFoundError:
        print(f"Erreur : Le fichier d'entrée '{input_excel_path}' n'a pas été trouvé.")
        return
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier Excel '{input_excel_path}': {e}")
        return

    required_cols = ['commit_url', 'filepath', 'line']
    missing_cols = [col for col in required_cols if col not in df_full.columns]
    if missing_cols:
        print(f"Erreur : Colonne(s) requise(s) manquante(s) dans l'Excel: {', '.join(missing_cols)}.")
        print(f"Colonnes disponibles : {df_full.columns.tolist()}")
        return

    # S'assurer que la colonne 'code_snippet' existe dans df_full et est de type object
    # pour éviter les TypeError plus tard, surtout si elle est remplie de NaN (float).
    if 'code_snippet' not in df_full.columns:
        df_full['code_snippet'] = pd.Series([pd.NA] * len(df_full), dtype="object")
    elif df_full['code_snippet'].dtype != 'object':
        print("Conversion de la colonne 'code_snippet' existante en type 'object' dans le DataFrame complet.")
        df_full['code_snippet'] = df_full['code_snippet'].astype(object)


    if num_rows_to_process is not None and num_rows_to_process < len(df_full):
        df_to_process = df_full.head(num_rows_to_process).copy() # .copy() est important ici
        print(f"Traitement des {num_rows_to_process} premières lignes pour le test.")
    else:
        df_to_process = df_full.copy() # Travailler sur une copie pour éviter SettingWithCopyWarning
        print(f"Traitement de toutes les {len(df_to_process)} lignes.")

    code_snippet_list_for_assignment = []

    for index, row in df_to_process.iterrows():
        excel_row_num = index + 1 # Utiliser l'index du DataFrame df_to_process pour le décompte
        original_excel_row_num = row.name + 1 if hasattr(row, 'name') else index +1 # Index original de df_full
        
        print(f"\nTraitement de la ligne Excel (index original {original_excel_row_num}) / {len(df_full)}...")
        commit_url = row['commit_url']
        filepath = row['filepath']
        line_excel_val = row['line']

        current_code_snippet = "N/A"

        line_type, val1, val2 = parse_line_input(line_excel_val)

        if line_type is None:
            msg = f"Erreur: 'line' ({line_excel_val}) invalide."
            print(f"  Ligne {original_excel_row_num}: {msg}")
            code_snippet_list_for_assignment.append(msg)
            continue
        
        fetch_start_line = -1
        fetch_end_line = -1

        if line_type == 'single':
            target_line = val1
            fetch_start_line = target_line - CONTEXT_LINES_FOR_SINGLE_LINE
            fetch_end_line = target_line + CONTEXT_LINES_FOR_SINGLE_LINE
            print(f"  Ligne cible unique: {target_line}. Extraction du contexte: L{fetch_start_line}-L{fetch_end_line}")
        elif line_type == 'range':
            range_start, range_end = val1, val2
            fetch_start_line = range_start - 1
            fetch_end_line = range_end + 1
            print(f"  Plage de lignes: ({range_start},{range_end}). Extraction étendue: L{fetch_start_line}-L{fetch_end_line}")
        
        fetch_start_line = max(1, fetch_start_line)

        owner, repo, commit_sha = parse_github_commit_url(commit_url)
        if not owner:
            msg = f"URL de commit invalide: {commit_url}"
            print(f"  Ligne {original_excel_row_num}: {msg}")
            code_snippet_list_for_assignment.append(msg)
            continue
            
        print(f"  Repo: {owner}/{repo}, Commit: {commit_sha}, Fichier: {filepath}")

        file_content, error_content = get_file_content_at_commit(owner, repo, filepath, commit_sha)

        if error_content:
            print(f"    Erreur lors de la récupération du contenu du fichier: {error_content}")
            current_code_snippet = error_content
        elif file_content is not None:
            current_code_snippet = extract_code_block_by_range(file_content, fetch_start_line, fetch_end_line)
            print(f"    Bloc de code extrait de L{fetch_start_line} à L{fetch_end_line}.")
        else:
            current_code_snippet = "Erreur inattendue: Contenu du fichier est None sans erreur."
            print(f"    {current_code_snippet}")
            
        code_snippet_list_for_assignment.append(current_code_snippet)

    # Assigner la liste des snippets au DataFrame df_to_process
    # S'assurer que la colonne 'code_snippet' existe et est de type objet dans df_to_process
    if 'code_snippet' not in df_to_process.columns:
        df_to_process['code_snippet'] = pd.Series(dtype='object') # Créer avec le bon type
    else:
        df_to_process['code_snippet'] = df_to_process['code_snippet'].astype(object) # Assurer le type

    # L'assignation doit se faire sur l'index de df_to_process
    if len(code_snippet_list_for_assignment) == len(df_to_process):
        df_to_process['code_snippet'] = code_snippet_list_for_assignment
    else:
        # Ce cas ne devrait pas arriver si la boucle est correcte
        print(f"Avertissement : La longueur de la liste des snippets ({len(code_snippet_list_for_assignment)}) ne correspond pas à df_to_process ({len(df_to_process)}). Assignation partielle.")
        # Gérer l'assignation partielle ou logguer une erreur plus sévère
        for i, snippet in enumerate(code_snippet_list_for_assignment):
            if i < len(df_to_process):
                df_to_process.iloc[i, df_to_process.columns.get_loc('code_snippet')] = snippet
    
    # Préparer le DataFrame final pour la sauvegarde
    if num_rows_to_process is not None and num_rows_to_process < len(df_full):
        # df_full a déjà la colonne 'code_snippet' (créée ou convertie au début)
        # Mettre à jour seulement les lignes traitées dans df_full
        df_full.loc[df_to_process.index, 'code_snippet'] = df_to_process['code_snippet']
        
        # Marquer les lignes non traitées dans df_full
        unprocessed_mask = ~df_full.index.isin(df_to_process.index)
        # Remplir 'code_snippet' pour les lignes non traitées seulement si elles sont NA après l'initialisation/conversion
        # (pour ne pas écraser des données si la colonne existait déjà avec des valeurs)
        df_full.loc[unprocessed_mask & df_full['code_snippet'].isna(), 'code_snippet'] = "Non traité (test)"
        df_output_final = df_full
    else:
        df_output_final = df_to_process # Toutes les lignes ont été traitées


    # Sélectionner et ordonner les colonnes pour la sortie finale (comme demandé)
    desired_output_columns = [
        'vulnerability', 'commit_url', 'filepath', 'line', 
        'location_start_column', 'location_end_column', 'code_snippet'
    ]
    
    # Créer le DataFrame de sortie final avec seulement les colonnes désirées
    df_final_selection = pd.DataFrame()
    for col_name in desired_output_columns:
        if col_name in df_output_final.columns:
            df_final_selection[col_name] = df_output_final[col_name]
        else:
            print(f"Information : La colonne désirée '{col_name}' n'a pas été trouvée dans les données traitées et sera ajoutée avec des valeurs vides/NA.")
            df_final_selection[col_name] = pd.NA # Créer la colonne avec NA


    try:
        df_final_selection.to_excel(output_excel_path, index=False, sheet_name='File_Snippets_Context_Final')
        print(f"\nFichier de sortie '{output_excel_path}' généré avec succès.")
        if num_rows_to_process is not None:
             print(f"Seules les {min(num_rows_to_process, len(df_full))} premières lignes ont été activement traitées.")
    except Exception as e:
        print(f"\nErreur lors de l'écriture du fichier de sortie '{output_excel_path}': {e}")


# --- Configuration ---
INPUT_EXCEL_FOR_CONTEXT_SNIPPETS_V3 = r"C:\\Users\\DELL\\Documents\\test_snyk\\test6-pulumi\\snykanalyse\\snyk_code_pulumi_corrected_without.xlsx"
OUTPUT_EXCEL_WITH_CONTEXT_SNIPPETS_V3 = r"C:\\Users\\DELL\\Documents\\test_snyk\\test6-pulumi\\snykanalyse\\pulumi_code_corrige.xlsx" # Nom de sortie modifié
NUM_ROWS_TO_TEST_CONTEXT_V3 = 46 # Mettre à None pour traiter toutes les lignes, ou un nombre pour tester
# --------------------

if __name__ == "__main__":
    process_file_content_for_snippets_v3(
        INPUT_EXCEL_FOR_CONTEXT_SNIPPETS_V3, 
        OUTPUT_EXCEL_WITH_CONTEXT_SNIPPETS_V3, 
        NUM_ROWS_TO_TEST_CONTEXT_V3
    )