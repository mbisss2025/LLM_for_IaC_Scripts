import pandas as pd

# === Modifier ce chemin avec le nom réel de votre fichier Excel ===
fichier_excel = "pulumi_total.xlsx"

# === Chargement du fichier Excel ===
df = pd.read_excel(fichier_excel)

# === Vérification que la colonne existe ===
if 'smell_category' not in df.columns:
    print("Erreur : La colonne 'smell_category' est absente du fichier.")
else:
    # === Comptage des occurrences ===
    counts = df['smell_category'].value_counts()

    # === Affichage des résultats ===
    print("Décompte des valeurs dans 'smell_category' :\n")
    print(counts)

    # === Sauvegarde dans un fichier CSV (facultatif) ===
    counts.to_csv("decompte_smell_category.csv", header=["Nombre"], index_label="smell_category")
