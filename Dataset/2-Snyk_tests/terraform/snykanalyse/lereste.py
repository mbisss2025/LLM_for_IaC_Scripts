import pandas as pd
import numpy as np # Pour np.nan

def find_rows_with_missing_snippets(input_excel_path, output_excel_path,
                                     snippet_column_name="code_snippet"):
    """
    Identifie les lignes d'un fichier Excel où la colonne de snippet de code est manquante
    ou indique une erreur, et les sauvegarde dans un nouveau fichier.

    Args:
        input_excel_path (str): Chemin vers le fichier Excel d'entrée.
        output_excel_path (str): Chemin pour sauvegarder le fichier Excel des entrées manquantes.
        snippet_column_name (str): Nom de la colonne contenant les snippets de code.
                                   Par défaut "code_snippet".
    """
    try:
        df = pd.read_excel(input_excel_path)
        print(f"Fichier d'entrée '{input_excel_path}' lu avec succès. Nombre de lignes total: {len(df)}")
    except FileNotFoundError:
        print(f"ERREUR : Le fichier d'entrée '{input_excel_path}' n'a pas été trouvé.")
        return
    except Exception as e:
        print(f"ERREUR : Impossible de lire le fichier Excel '{input_excel_path}': {e}")
        return

    if snippet_column_name not in df.columns:
        print(f"ERREUR : La colonne '{snippet_column_name}' n'est pas présente dans le fichier Excel.")
        print(f"Colonnes disponibles : {df.columns.tolist()}")
        return

    # Définir les conditions pour qu'un snippet soit considéré comme "manquant" ou "invalide"
    # 1. Valeurs NaN (non défini)
    # 2. Chaînes vides ou ne contenant que des espaces
    # 3. Chaînes spécifiques indiquant une erreur ou un non-traitement
    
    # Convertir la colonne en chaînes pour une manipulation plus facile, en gardant les NaN
    # df[snippet_column_name] = df[snippet_column_name].astype(str) # Cela convertit NaN en "nan" string
    # Il est préférable de travailler avec les NaN directement pour la première condition.

    # Condition 1: est NaN
    condition_nan = df[snippet_column_name].isna()

    # Condition 2: est une chaîne vide ou ne contient que des espaces
    # Appliquer seulement aux non-NaN pour éviter les erreurs de type avec .str sur des floats (si NaN est float)
    condition_empty_whitespace = df[snippet_column_name].fillna('').astype(str).str.strip() == ""

    # Condition 3: Chaînes spécifiques (insensible à la casse pour "erreur", "non traité")
    # S'assurer que ce sont des chaînes avant d'appeler .str
    df_str_col = df[snippet_column_name].astype(str).str.lower()
    
    error_placeholders = [
        "erreur:",  # Couvre "Erreur: ..."
        "n/a",
        "non traité", # Couvre "Non traité (test)"
        "fichier non trouvé",
        "timeout lors de la récupération",
        "le chemin", # Couvre "Le chemin '...' est un répertoire"
        "contenu vide",
        "paramètres manquants",
        "url de commit invalide"
    ]
    
    condition_error_strings = pd.Series([False] * len(df)) # Initialiser à False
    # Appliquer la recherche de sous-chaîne seulement aux valeurs qui sont des chaînes
    non_na_mask = df[snippet_column_name].notna()
    for placeholder in error_placeholders:
        condition_error_strings.loc[non_na_mask] = condition_error_strings.loc[non_na_mask] | \
                                                   df_str_col[non_na_mask].str.contains(placeholder, case=False, na=False)


    # Combiner toutes les conditions pour identifier une ligne comme "manquante"
    missing_snippet_mask = condition_nan | condition_empty_whitespace | condition_error_strings
    
    df_missing_snippets = df[missing_snippet_mask]
    
    num_missing = len(df_missing_snippets)

    if num_missing > 0:
        print(f"{num_missing} ligne(s) avec un snippet de code manquant ou invalide ont été identifiées.")
        try:
            df_missing_snippets.to_excel(output_excel_path, index=False)
            print(f"Les lignes avec des snippets manquants ont été sauvegardées dans '{output_excel_path}'.")
        except Exception as e:
            print(f"ERREUR : Impossible d'écrire le fichier Excel de sortie '{output_excel_path}': {e}")
    else:
        print("Bonne nouvelle ! Aucune ligne avec un snippet de code manquant ou invalide n'a été trouvée.")

# --- Configuration ---
# REMPLACEZ CES VALEURS SI NÉCESSAIRE

# Fichier Excel d'entrée (celui qui devrait contenir la colonne 'code_snippet')
INPUT_EXCEL_FILE = r"C:\\Users\\DELL\\Documents\\test_snyk\\Test5-chef\\snykanalyse\\chef_snyk_analysis_final\\chef_snyk_code_analysis_final.xlsx" # Ou "snyk_analysis_context_snippets_v3.xlsx", etc.

# Nom du fichier Excel de sortie pour les lignes avec snippets manquants
OUTPUT_MISSING_SNIPPETS_FILE =  r"C:\\Users\\DELL\\Documents\\test_snyk\\Test5-chef\\snykanalyse\\entrees_manquants.xlsx"

# Nom de la colonne dans votre fichier Excel qui contient les snippets de code
SNIPPET_COLUMN = "code_snippet"
# --------------------

if __name__ == "__main__":
    find_rows_with_missing_snippets(
        INPUT_EXCEL_FILE,
        OUTPUT_MISSING_SNIPPETS_FILE,
        SNIPPET_COLUMN
    )