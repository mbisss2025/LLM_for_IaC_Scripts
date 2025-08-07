import pandas as pd
import requests
import base64
import re
import os
from urllib.parse import urlparse

# --- Configuration ---
# Token GitHub (TRÈS IMPORTANT)
GITHUB_TOKEN = "YOUR_GITHUB_TOKEN"
if not GITHUB_TOKEN:
    GITHUB_TOKEN = input("Veuillez entrer votre token d'accès personnel GitHub : ")

HEADERS = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json',
}

# Nombre de lignes de contexte si la 'line_number' est un seul numéro
CONTEXT_LINES_FOR_SINGLE_LINE = 2

# --- Fonctions Utilitaires (inchangées) ---

def parse_github_commit_url(url_str):
    if not isinstance(url_str, str):
        return None, None, None
    try:
        if not url_str.startswith(('http://', 'https://')):
            url_str = 'https://' + url_str
        
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
        content_base64 = response.json().get('content')
        if content_base64:
            return base64.b64decode(content_base64).decode('utf-8'), None
        else:
            file_type = response.json().get('type')
            if file_type == 'dir':
                return None, f"Le chemin '{filepath}' est un répertoire, pas un fichier."
            return None, "Contenu vide ou fichier non trouvé (pas de champ 'content')."
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            return None, f"Fichier non trouvé (404) : {filepath} au commit {sha} dans {owner}/{repo}."
        elif response.status_code == 403:
             try:
                error_details = response.json().get('message', str(http_err))
                if "too large" in error_details.lower():
                     return None, f"Fichier trop volumineux (403) : {filepath}. API Contents limitée à 1Mo. Erreur: {error_details}"
                else:
                    return None, f"Erreur HTTP 403 (Forbidden) : {filepath} au commit {sha}. Vérifiez les permissions du token. Détails: {error_details}"
             except:
                return None, f"Erreur HTTP 403 (Forbidden) : {filepath} au commit {sha}. Détails: {str(http_err)}"
        return None, f"Erreur HTTP lors de la récupération du fichier : {http_err} pour {api_url}"
    except requests.exceptions.Timeout:
        return None, f"Timeout lors de la récupération du fichier {filepath} à {sha} pour {api_url}"
    except Exception as e:
        return None, f"Erreur lors de la récupération du contenu du fichier {filepath} à {sha}: {e} pour {api_url}"

def parse_line_input_for_iac(line_val_from_excel):
    if pd.isna(line_val_from_excel):
        return None, None, None
    if isinstance(line_val_from_excel, (int, float)):
        num_line = int(line_val_from_excel)
        return 'single', num_line, num_line
    if isinstance(line_val_from_excel, str):
        match_tuple = re.match(r'\((\d+),\s*(\d+)\)', line_val_from_excel)
        if match_tuple:
            start_r, end_r = int(match_tuple.group(1)), int(match_tuple.group(2))
            if start_r > end_r: start_r, end_r = end_r, start_r
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


def process_iac_report_for_snippets_v3( # Renommé pour indiquer la nouvelle version
    input_excel_path,
    output_excel_path,
    repo_url_col='nom_repo',
    commit_sha_col='commit_sha',
    filepath_col='target_file',
    line_col='line_number',
    vulnerability_desc_col='description', # Nouvelle config pour la source de 'vulnerability'
    location_start_col_name='location_start_column', # Ajouté pour flexibilité
    location_end_col_name='location_end_column',     # Ajouté pour flexibilité
    num_rows_to_process=None
):
    """
    Charge un rapport Snyk IaC enrichi, construit l'URL de commit, 
    récupère le contenu du fichier, extrait un bloc de code, et formate la sortie.
    """
    try:
        df_full = pd.read_excel(input_excel_path)
        print(f"Fichier d'entrée '{input_excel_path}' lu avec succès ({len(df_full)} lignes).")
    except FileNotFoundError:
        print(f"Erreur : Le fichier d'entrée '{input_excel_path}' n'a pas été trouvé.")
        return
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier Excel '{input_excel_path}': {e}")
        return

    required_input_cols = [repo_url_col, commit_sha_col, filepath_col, line_col, vulnerability_desc_col]
    # location_start_column et location_end_column sont optionnelles pour cette fonction,
    # mais seront incluses dans la sortie si elles existent.
    
    missing_input_cols = [col for col in required_input_cols if col not in df_full.columns]
    if missing_input_cols:
        print(f"Erreur : Colonne(s) d'entrée requise(s) manquante(s) : {', '.join(missing_input_cols)}.")
        print(f"Colonnes disponibles : {df_full.columns.tolist()}")
        return

    if num_rows_to_process is not None and num_rows_to_process < len(df_full):
        df_to_process = df_full.head(num_rows_to_process).copy()
        print(f"Traitement des {num_rows_to_process} premières lignes pour le test.")
    else:
        df_to_process = df_full.copy()
        print(f"Traitement de toutes les {len(df_to_process)} lignes.")

    # Initialiser les listes pour les NOUVELLES colonnes ou celles qui seront MODIFIÉES
    code_snippet_list = []
    constructed_commit_url_list = []
    parsed_line_list = [] # Pour stocker la version parsée/formatée de la colonne 'line'

    for index, row in df_to_process.iterrows():
        excel_row_num = row.name + 1 # Utiliser l'index original de df_full pour les messages
        print(f"\nTraitement de la ligne Excel {excel_row_num}/{len(df_full)}...")
        
        repo_url_val = row[repo_url_col]
        commit_sha_val = row[commit_sha_col]
        filepath_val = row[filepath_col]
        if pd.notna(filepath_val) and isinstance(filepath_val, str):
            filepath_val = filepath_val.replace('\\', '/').strip()
        else:
            msg = f"Valeur de filepath invalide ou manquante: {filepath_val}"
            print(f"  Ligne {excel_row_num}: {msg}")
            code_snippet_list.append(msg) # ou la liste appropriée pour l'erreur
            # ... (si vous avez plusieurs listes pour les résultats)
            continue # Passer à la ligne suivante
        line_excel_val = row[line_col]

        current_code_snippet = "N/A"
        current_constructed_commit_url = "N/A"
        current_parsed_line_output = "N/A"


        # --- Construction de l'URL de commit ---
        if pd.notna(repo_url_val) and isinstance(repo_url_val, str) and repo_url_val.strip() and \
           pd.notna(commit_sha_val) and isinstance(commit_sha_val, str) and commit_sha_val.strip():
            
            cleaned_repo_url = repo_url_val.strip()
            if cleaned_repo_url.endswith('/'):
                cleaned_repo_url = cleaned_repo_url[:-1]
            current_constructed_commit_url = f"{cleaned_repo_url}/commit/{commit_sha_val.strip()}"
        else:
            current_constructed_commit_url = "Erreur: Données repo/sha manquantes"
        
        constructed_commit_url_list.append(current_constructed_commit_url)

        line_type, val1, val2 = parse_line_input_for_iac(line_excel_val)

        if line_type is None:
            msg = f"Erreur: '{line_col}' ({line_excel_val}) invalide."
            print(f"  Ligne {excel_row_num}: {msg}")
            code_snippet_list.append(msg)
            parsed_line_list.append(line_excel_val) # Garder la valeur originale si erreur
            continue
        
        # Formatage de la sortie 'line'
        if line_type == 'single':
            current_parsed_line_output = val1
        elif line_type == 'range':
            current_parsed_line_output = f"({val1}, {val2})"
        parsed_line_list.append(current_parsed_line_output)

        fetch_start_line = -1
        fetch_end_line = -1

        if line_type == 'single':
            target_line = val1
            fetch_start_line = target_line - CONTEXT_LINES_FOR_SINGLE_LINE
            fetch_end_line = target_line + CONTEXT_LINES_FOR_SINGLE_LINE
        elif line_type == 'range':
            range_start, range_end = val1, val2
            fetch_start_line = range_start - 1 
            fetch_end_line = range_end + 1   
        
        fetch_start_line = max(1, fetch_start_line)

        # Continuer seulement si l'URL de commit a pu être construite
        if "Erreur:" in current_constructed_commit_url:
            print(f"  Ligne {excel_row_num}: {current_constructed_commit_url}. Impossible de récupérer le code.")
            code_snippet_list.append(current_constructed_commit_url) # Reporter l'erreur de l'URL
            continue

        owner, repo, parsed_sha_from_url = parse_github_commit_url(current_constructed_commit_url)
        if not owner:
            msg = f"URL de commit construite invalide ou impossible à analyser : {current_constructed_commit_url}"
            print(f"  Ligne {excel_row_num}: {msg}")
            code_snippet_list.append(msg)
            continue
            
        print(f"  Analyse API: Repo: {owner}/{repo}, Commit: {commit_sha_val}, Fichier: {filepath_val}, Plage: L{fetch_start_line}-L{fetch_end_line}")

        file_content, error_content = get_file_content_at_commit(owner, repo, filepath_val, commit_sha_val)

        if error_content:
            print(f"    Erreur lors de la récupération du contenu du fichier: {error_content}")
            current_code_snippet = error_content
        elif file_content is not None:
            current_code_snippet = extract_code_block_by_range(file_content, fetch_start_line, fetch_end_line)
            print(f"    Bloc de code extrait.")
        else:
            current_code_snippet = "Erreur inattendue: Contenu du fichier est None sans erreur."
            print(f"    {current_code_snippet}")
            
        code_snippet_list.append(current_code_snippet)

    # Assigner les listes au DataFrame (qu'il soit complet ou partiel)
    df_to_process.loc[:, 'code_snippet_generated'] = code_snippet_list # Nom temporaire pour éviter conflit
    df_to_process.loc[:, 'commit_url_generated'] = constructed_commit_url_list
    df_to_process.loc[:, 'line_formatted'] = parsed_line_list
    
    # Préparer le DataFrame final pour la sauvegarde
    if num_rows_to_process is not None and num_rows_to_process < len(df_full):
        df_output_final = df_full.copy() # Commencer avec toutes les colonnes originales
        # Mettre à jour les colonnes pour les lignes traitées
        for col_temp, col_final in [('code_snippet_generated', 'code_snippet'), 
                                    ('commit_url_generated', 'commit_url'), # Écrase commit_url original si existe
                                    ('line_formatted', 'line')]: # Écrase line original si existe
            if col_final not in df_output_final.columns:
                 df_output_final[col_final] = pd.NA
            df_output_final.loc[df_to_process.index, col_final] = df_to_process[col_temp]
            
            unprocessed_mask = ~df_output_final.index.isin(df_to_process.index)
            # Pour les lignes non traitées, conserver la valeur originale de 'commit_url' et 'line'
            # et mettre "Non traité" pour 'code_snippet'
            if col_final == 'code_snippet':
                 df_output_final.loc[unprocessed_mask, col_final] = df_output_final.loc[unprocessed_mask, col_final].fillna("Non traité (test)")
            # Pour 'commit_url' et 'line', les valeurs originales des lignes non traitées sont déjà là
            # si on part de df_full.copy(). Si elles ont été écrasées par pd.NA, il faut les restaurer
            # ou s'assurer qu'elles ne sont écrasées que pour les lignes traitées.
            # La logique ci-dessus avec df_output_final.loc[df_to_process.index, col_final] le fait correctement.
            # Si la colonne col_final (ex: 'commit_url') n'existait pas dans df_full, elle est créée avec NA
            # puis remplie pour les lignes traitées. Les lignes non traitées restent NA.
            # C'est acceptable.

    else: # Toutes les lignes ont été traitées ou le DataFrame de départ était déjà le sous-ensemble
        df_output_final = df_to_process.copy() # Utiliser la copie pour éviter d'altérer df_to_process si on la réutilise
        # Renommer les colonnes générées aux noms finaux
        df_output_final.rename(columns={
            'code_snippet_generated': 'code_snippet',
            'commit_url_generated': 'commit_url',
            'line_formatted': 'line'
        }, inplace=True)


    # Sélectionner et ordonner les colonnes pour la sortie finale
    desired_output_columns = [
        'vulnerability',          # Source: vulnerability_desc_col
        'commit_url',             # Source: Générée (commit_url_generated)
        'filepath',               # Source: filepath_col
        'line',                   # Source: Générée (line_formatted)
        location_start_col_name,  # Source: location_start_col_name
        location_end_col_name,    # Source: location_end_col_name
        'code_snippet'            # Source: Générée (code_snippet_generated)
    ]
    
    # Mapping des noms de colonnes de sortie vers les sources dans df_output_final
    # La colonne 'vulnerability' dans la sortie vient de 'vulnerability_desc_col' dans l'entrée.
    # La colonne 'filepath' dans la sortie vient de 'filepath_col' dans l'entrée.
    # 'commit_url' et 'line' dans la sortie sont celles que nous venons de générer/formater.
    # 'code_snippet' aussi.
    
    df_final_selection = pd.DataFrame()
    df_final_selection['vulnerability'] = df_output_final[vulnerability_desc_col] if vulnerability_desc_col in df_output_final else pd.NA
    df_final_selection['commit_url'] = df_output_final['commit_url'] # Déjà renommée si toutes les lignes traitées
    df_final_selection['filepath'] = df_output_final[filepath_col] if filepath_col in df_output_final else pd.NA
    df_final_selection['line'] = df_output_final['line'] # Déjà renommée
    
    if location_start_col_name in df_output_final.columns:
        df_final_selection['location_start_column'] = df_output_final[location_start_col_name]
    else:
        df_final_selection['location_start_column'] = pd.NA
        
    if location_end_col_name in df_output_final.columns:
        df_final_selection['location_end_column'] = df_output_final[location_end_col_name]
    else:
        df_final_selection['location_end_column'] = pd.NA
        
    df_final_selection['code_snippet'] = df_output_final['code_snippet']

    # Réassigner les noms de colonnes pour correspondre exactement à la sortie désirée
    df_final_selection.columns = [
        'vulnerability', 'commit_url', 'filepath', 'line',
        'location_start_column', 'location_end_column', 'code_snippet'
    ]


    try:
        df_final_selection.to_excel(output_excel_path, index=False, sheet_name='IaC_Snippets_Formatted')
        print(f"\nFichier de sortie '{output_excel_path}' généré avec succès avec la structure de colonnes demandée.")
        if num_rows_to_process is not None:
             print(f"Seules les {min(num_rows_to_process, len(df_full))} premières lignes ont été activement traitées.")

    except Exception as e:
        print(f"\nErreur lors de l'écriture du fichier de sortie '{output_excel_path}': {e}")


# --- Configuration ---
INPUT_EXCEL_IAC_ENRICHED_V3 = "snyk_iac_results.xlsx" 

# Noms des colonnes dans INPUT_EXCEL_IAC_ENRICHED_V3
REPO_URL_COL_CFG = "nom_repo"         
COMMIT_SHA_COL_CFG = "commit_sha"     
FILEPATH_COL_IAC_CFG = "target_file"
LINE_NUMBER_COL_IAC_CFG = "line_number"
VULNERABILITY_DESCRIPTION_COL_CFG = "description" # Source pour la colonne 'vulnerability'
# Optionnel: si vos colonnes location_start/end_column ont d'autres noms
LOCATION_START_COLUMN_CFG = "location_start_column" # Supposons qu'elle existe, sinon sera NA
LOCATION_END_COLUMN_CFG = "location_end_column"     # Supposons qu'elle existe, sinon sera NA


OUTPUT_EXCEL_IAC_FINAL_FORMAT = "iac-results_again.xlsx"
NUM_ROWS_TO_TEST_IAC_FINAL = None # Mettre à None pour traiter toutes les lignes
# --------------------

if __name__ == "__main__":
    if not GITHUB_TOKEN or len(GITHUB_TOKEN) < 20:
        print("ERREUR CRITIQUE : Le token d'accès personnel GitHub n'est pas configuré ou semble invalide.")
    else:
        process_iac_report_for_snippets_v3(
            INPUT_EXCEL_IAC_ENRICHED_V3, 
            OUTPUT_EXCEL_IAC_FINAL_FORMAT,
            repo_url_col=REPO_URL_COL_CFG,
            commit_sha_col=COMMIT_SHA_COL_CFG,
            filepath_col=FILEPATH_COL_IAC_CFG,
            line_col=LINE_NUMBER_COL_IAC_CFG,
            vulnerability_desc_col=VULNERABILITY_DESCRIPTION_COL_CFG,
            location_start_col_name=LOCATION_START_COLUMN_CFG,
            location_end_col_name=LOCATION_END_COLUMN_CFG,
            num_rows_to_process=NUM_ROWS_TO_TEST_IAC_FINAL
        )