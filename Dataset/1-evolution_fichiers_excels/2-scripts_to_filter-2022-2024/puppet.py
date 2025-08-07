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
        "Outdated Dependencies": ['require', 'dependency', 'version <', 'lockfile missing', 'dependency outdated'],
        "Path Traversal": ['../', '..\\', '../../../', 'directory traversal', 'file path manipulation'],
        "Sensitive Information Exposure": [
            'password', 'secret', 'api_key', 'access_token', 'private_key', 'credentials', 'secret_key'
        ],
        "Code Injection": ['eval', 'templatefile', 'inline_template', 'code injection', 'dynamic code'],
        "Command Injection": ['shell', 'exec', 'command', 'system(', 'popen', 'os.system', 'subprocess'],
        "Insecure Input Handling": ['input(', 'deserialize', 'yaml.load', 'no input validation'],
        "Insecure Dependency Management": ['dependency', 'source =', 'git::', 'dependency hijacking'],
        "Inadequate Naming Convention": ['badname', 'uglyname', 'invalid_name', 'wrong_case']
    }

    return any(p in text for p in patterns.get(smell_category, []))


def codes_equivalents(code1, code2):
    try:
        return ast.dump(ast.parse(str(code1).strip())) == ast.dump(ast.parse(str(code2).strip()))
    except Exception:
        norm = lambda c: re.sub(r'\s+', '', str(c).strip())
        return norm(code1) == norm(code2)


def is_vagrant_config_file(filepath, code=None):
    if not isinstance(filepath, str):
        return False
    filename = os.path.basename(filepath).lower()
    if filename == 'vagrantfile':
        return True
    if filepath.endswith('.rb') and code:
        code_text = str(code).lower()
        return 'vagrant' in code_text or 'config.vm' in code_text
    return False


def construire_dataset(filepath_excel,
                       output_file=r"C:\Users\DELL\Documents\DIC3 Docs\Lux\sujet\reports\2022-2024\dataset_vagrant_2022_2024.xlsx"):
    df = pd.read_excel(filepath_excel)

    colonnes = [
        'smell_category', 'commit_url', 'filepath',
        'previous_lines', 'after_lines',
        'previous_code', 'after_code', 'commit_message',
        'year_2022', 'year_2023', 'year_2024'
    ]
    df = df[colonnes]

    df = df[(df['year_2022'] == 1) | (df['year_2023'] == 1) | (df['year_2024'] == 1)]
    df = df[~df.apply(lambda row: codes_equivalents(row['previous_code'], row['after_code']), axis=1)]
    df = df[df.apply(lambda row: is_vagrant_config_file(row['filepath'], row['previous_code']), axis=1)]
    # 🔧 Correction des caractères échappés comme \$ → $
    for col in ['previous_code', 'after_code', 'commit_message']:
        df[col] = df[col].astype(str).str.replace(r'\\\$', '$', regex=True)


    df['bloc_text'] = df['previous_code'].fillna('') + " " + df['after_code'].fillna('') + " " + df['commit_message'].fillna('')
    df['vulnerabilite_valide'] = df.apply(lambda row: detecte_vulnerabilite_generic(row['bloc_text'], row['smell_category']), axis=1)

    df = df[df['vulnerabilite_valide']].copy()
    df.drop(columns=['bloc_text', 'vulnerabilite_valide'], inplace=True)

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    df.to_excel(output_file, index=False)
    print(f"✅ Fichier exporté : {output_file} ({len(df)} lignes)")

    return df


if __name__ == "__main__":
    fichier_entree = r"C:\Users\DELL\Documents\DIC3 Docs\Lux\sujet\reports\evolution_fichiers_excels\Vagrant_report.xlsx"
    construire_dataset(fichier_entree)