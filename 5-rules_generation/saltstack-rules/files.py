import pandas as pd
import os
import re

def extract_rules_and_tests(excel_path, output_dir="rules_output", output_excel="validated_rules_output.xlsx"):
    os.makedirs(output_dir, exist_ok=True)
    df = pd.read_excel(excel_path)

    if 'generated_salt_lint_rule' not in df.columns or 'code_snippet' not in df.columns:
        print("❌ Les colonnes 'generated_salt_lint_rule' et/ou 'code_snippet' sont absentes.")
        return

    validated_contents = []

    for idx, row in df.iterrows():
        rule_code = row.get('generated_salt_lint_rule')
        snippet_code = row.get('code_snippet')

        rule_index = idx + 1
        security_id = f"SECURITY{rule_index:03d}"

        validated_rule_content = ""

        ### ----- Traitement de generated_salt_lint_rule -----
        if pd.notna(rule_code):
            match = re.search(r'class\s+(\w+)\s*\(', rule_code)
            if match:
                original_class = match.group(1)
                new_class = f"{original_class}{rule_index}"

                updated_code = re.sub(rf'\bclass\s+{original_class}\b', f'class {new_class}', rule_code)

                updated_code = re.sub(
                    rf"(alias\s*=\s*['\"]?){original_class}(['\"]?)",
                    rf"\1{new_class}\2",
                    updated_code
                )

                updated_code = re.sub(
                    r"id\s*=\s*['\"]?[\w\-]+['\"]?",
                    f"id = '{security_id}'",
                    updated_code
                )

                updated_code = re.sub(
                    rf"(\b\w+\s*=\s*){original_class}\b",
                    rf"\1{new_class}",
                    updated_code
                )

                updated_lines = []
                for line in updated_code.splitlines():
                    m = re.match(r"^(\s*)(\w+)\s*=\s*" + re.escape(new_class) + r"\b", line)
                    if m:
                        new_var_name = f"{m.group(2)}{rule_index}"
                        updated_lines.append(f"{m.group(1)}{new_var_name} = {new_class}")
                    else:
                        updated_lines.append(line)

                final_code = '\n'.join(updated_lines)
                validated_rule_content = final_code

                rule_file = os.path.join(output_dir, f"{new_class}.py")
                with open(rule_file, 'w', encoding='utf-8') as f:
                    f.write(final_code)
                print(f"✅ Règle écrite dans {rule_file} avec id '{security_id}'")

        validated_contents.append(validated_rule_content)

        ### ----- Traitement de code_snippet -----
        if pd.notna(snippet_code):
            test_file = os.path.join(output_dir, f"test_salt{rule_index}.py")
            with open(test_file, 'w', encoding='utf-8') as f:
                f.write(str(snippet_code))
            print(f"✅ Snippet écrit dans test_salt{rule_index}.py")

    # Ajout de la colonne validated_rules contenant le code Python modifié
    df["validated_rules"] = validated_contents

    # Sauvegarde du nouveau fichier Excel
    df.to_excel(output_excel, index=False)
    print(f"\n📄 Nouveau fichier Excel avec contenu dans 'validated_rules' : {output_excel}")



# Exemple d’utilisation
if __name__ == "__main__":
    fichier_excel = "resultats_avec_salt.xlsx"  # Remplacez par le nom de votre fichier Excel
    extract_rules_and_tests(fichier_excel)
