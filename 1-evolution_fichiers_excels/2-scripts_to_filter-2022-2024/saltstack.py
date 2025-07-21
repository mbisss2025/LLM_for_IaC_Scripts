import pandas as pd
import os
import re
import ast

def detecte_vulnerabilite_generic(text_snippet, smell_category):
    text = str(text_snippet).lower()
    patterns = {
        "Outdated Software Version": ['version', '2018', '2019', '"1.', '"2.', 'deprecated', 'old_version', 'legacy'],
        "Insecure Configuration Management": [
            'ssl_verify = false', 'skip_ssl_validation', 'insecure = true', 'validate_tls = false',
            'allow_insecure', 'disable_ssl', 'skip_tls_verify', 'allow_unverified_ssl',
            'verify_ssl: false', 'validate_certs: false'
        ],
        "Outdated Dependencies": [
            'require', 'dependency', 'version <', 'lockfile missing', 'dependency outdated',
            'update dependency', 'old package'
        ],
        "Path Traversal": ['../', '..\\', '../../../', 'directory traversal', 'file path manipulation'],
        "Sensitive Information Exposure": [
            'password', 'secret', 'api_key', 'access_token', 'private_key', 'credentials',
            'secret_key', 'hardcoded credentials'
        ],
        "Code Injection": [
            'eval', 'templatefile', 'inline_template', 'dynamic code', 'code injection',
            'untrusted input', 'unsafe eval'
        ],
        "Command Injection": [
            'shell', 'exec', 'command', 'local-exec', 'system(', 'popen', 'os.system', 'subprocess'
        ],
        "Insecure Input Handling": [
            'input(', 'deserialize', 'yaml.load', 'unsafe deserialization', 'no input validation',
            'input validation missing'
        ],
        "Insecure Dependency Management": [
            'dependency', 'package', 'source =', 'git::', 'pinned version missing',
            'requirement not specified', 'dependency confusion', 'dependency hijacking'
        ],
        "Inadequate Naming Convention": [
            'badname', 'uglyname', 'invalid_name', 'wrong_case', 'not_snake_case', 'improper naming'
        ]
    }
    return any(p in text for p in patterns.get(smell_category, []))


def construire_dataset_saltstack(filepath_excel,
                                 output_valid=r"C:\Users\DELL\Documents\DIC3 Docs\Lux\sujet\reports\2022-2024\dataset_saltstack_2022_2024.xlsx",
                                 output_rejetes=r"C:\Users\DELL\Documents\DIC3 Docs\Lux\sujet\reports\2022-2024\rejected_saltstack_2022_2024.xlsx"):
    df = pd.read_excel(filepath_excel)

    colonnes_cibles = [
        'smell_category', 'commit_url', 'filepath',
        'previous_lines', 'after_lines',
        'previous_code', 'after_code', 'commit_message',
        'year_2022', 'year_2023', 'year_2024'
    ]
    df = df[colonnes_cibles]

    # Ne garder que les lignes des années ciblées
    df = df[(df['year_2022'] == 1) | (df['year_2023'] == 1) | (df['year_2024'] == 1)]

    # Détection vulnérabilité
    df['bloc_text'] = df['previous_code'].fillna('') + " " + df['after_code'].fillna('') + " " + df['commit_message'].fillna('')
    df['vulnerabilite_valide'] = df.apply(lambda row: detecte_vulnerabilite_generic(row['bloc_text'], row['smell_category']), axis=1)

    # Séparation valides / rejetés
    df_valides = df[df['vulnerabilite_valide']].copy()
    df_rejetes = df[~df['vulnerabilite_valide']].copy()

    # Nettoyage colonnes temporaires
    for d in [df_valides, df_rejetes]:
        d.drop(columns=['bloc_text', 'vulnerabilite_valide'], inplace=True, errors='ignore')

    # Sauvegarde des fichiers
    os.makedirs(os.path.dirname(output_valid), exist_ok=True)
    df_valides.to_excel(output_valid, index=False)
    df_rejetes.to_excel(output_rejetes, index=False)

    print(f"✅ Export terminé : {len(df_valides)} valides, {len(df_rejetes)} rejetées")
    return df_valides, df_rejetes


# Exemple d'appel
if __name__ == "__main__":
    fichier_entree = r"C:\Users\DELL\Documents\DIC3 Docs\Lux\sujet\reports\evolution_fichiers_excels\Saltstack_report.xlsx"
    construire_dataset_saltstack(fichier_entree)
