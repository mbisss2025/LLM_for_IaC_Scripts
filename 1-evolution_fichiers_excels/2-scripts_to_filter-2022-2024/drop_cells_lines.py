import pandas as pd
import os

# === Paramètres ===
fichier_entree = r"C:\Users\DELL\Documents\DIC3 Docs\Lux\sujet\reports\2022-2024\dataset_vagrant_2022_2024.xlsx"
fichier_sortie = r"C:\Users\DELL\Documents\DIC3 Docs\Lux\sujet\reports\2022-2024\dataset_vagrant.xlsx"

# === Charger le fichier Excel ===
df = pd.read_excel(fichier_entree)

# Supprimer les lignes où le previous_code est une indication de fin de fichier sans contenu
df = df[~df['previous_code'].astype(str).str.strip().isin(['\\ No newline at end of file'])]

# === Supprimer les lignes avec previous_code vide ou NaN ===
df_filtré = df[df['previous_code'].notna() & (df['previous_code'].astype(str).str.strip() != '')]



# === Exporter le fichier filtré ===
os.makedirs(os.path.dirname(fichier_sortie), exist_ok=True)
df_filtré.to_excel(fichier_sortie, index=False)

print(f"✅ Fichier exporté : {fichier_sortie} ({len(df_filtré)} lignes restantes)")
