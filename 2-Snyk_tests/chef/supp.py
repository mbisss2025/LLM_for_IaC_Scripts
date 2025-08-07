import pandas as pd
import numpy as np # Pour np.nan si nécessaire

def remove_rows_with_empty_commit_url(input_excel_path, output_excel_path,
                                      commit_url_column_name="commit_url"):
    """
    Supprime les lignes d'un fichier Excel où la colonne 'commit_url' spécifiée est vide.

    Args:
        input_excel_path (str): Chemin vers le fichier Excel d'entrée.
        output_excel_path (str): Chemin pour sauvegarder le fichier Excel modifié.
        commit_url_column_name (str): Nom de la colonne contenant les URLs de commit.
                                      Par défaut "commit_url".
    """
    try:
        df = pd.read_excel(input_excel_path)
        print(f"Fichier d'entrée '{input_excel_path}' lu avec succès. Nombre de lignes initial: {len(df)}")
    except FileNotFoundError:
        print(f"ERREUR : Le fichier d'entrée '{input_excel_path}' n'a pas été trouvé.")
        return
    except Exception as e:
        print(f"ERREUR : Impossible de lire le fichier Excel '{input_excel_path}': {e}")
        return

    if commit_url_column_name not in df.columns:
        print(f"ERREUR : La colonne '{commit_url_column_name}' n'est pas présente dans le fichier Excel.")
        print(f"Colonnes disponibles : {df.columns.tolist()}")
        return

    # Enregistrer le nombre de lignes avant suppression
    initial_rows = len(df)

    # Identifier les lignes où 'commit_url' est NaN (vide lu par pandas) ou une chaîne vide après suppression des espaces
    # Remplacer les chaînes composées uniquement d'espaces par NaN pour qu'elles soient aussi supprimées
    df[commit_url_column_name] = df[commit_url_column_name].replace(r'^\s*$', np.nan, regex=True)
    
    # Supprimer les lignes où la colonne commit_url est NaN (ce qui inclut les vides et les espaces blancs)
    df_cleaned = df.dropna(subset=[commit_url_column_name])
    
    rows_removed_count = initial_rows - len(df_cleaned)

    if rows_removed_count > 0:
        print(f"{rows_removed_count} ligne(s) avec une colonne '{commit_url_column_name}' vide ont été supprimées.")
    else:
        print(f"Aucune ligne avec une colonne '{commit_url_column_name}' vide n'a été trouvée.")

    try:
        df_cleaned.to_excel(output_excel_path, index=False)
        print(f"Fichier modifié sauvegardé avec succès sous '{output_excel_path}'. Nombre de lignes final: {len(df_cleaned)}")
    except Exception as e:
        print(f"ERREUR : Impossible d'écrire le fichier Excel de sortie '{output_excel_path}': {e}")

# --- Configuration ---
# REMPLACEZ CES VALEURS PAR VOS NOMS DE FICHIERS ET DE COLONNES

# Fichier Excel d'entrée
INPUT_EXCEL_FILE = r"C:\\Users\\DELL\\Documents\\test_snyk\\test9_vagrant\\snykanalyse\\snyk_code_without.xlsx" # Ou un autre fichier comme "snyk_code_results_enriched.xlsx"

# Nom du fichier Excel de sortie après suppression des lignes vides
OUTPUT_EXCEL_FILE_NO_EMPTY_URL = r"C:\\Users\\DELL\\Documents\\test_snyk\\test8_terraform\\snykanalyse\\snyk_code_without.xlsx_cleaned.xlsx"

# Nom de la colonne dans votre fichier Excel qui contient les URLs de commit
COMMIT_URL_COLUMN_TO_CHECK = "commit_url"
# --------------------

if __name__ == "__main__":
    remove_rows_with_empty_commit_url(
        INPUT_EXCEL_FILE,
        OUTPUT_EXCEL_FILE_NO_EMPTY_URL,
        COMMIT_URL_COLUMN_TO_CHECK
    )

