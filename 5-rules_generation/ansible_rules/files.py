import pandas as pd
import os
import re

def extract_rules_and_tests(excel_path, output_dir="rules_output", output_excel="validated_rules_output.xlsx"):
    os.makedirs(output_dir, exist_ok=True)
    df = pd.read_excel(excel_path)

    required_columns = {'generated_ansible_lint_rule', 'code_snippet', 'smell_category', 'filepath'}
    if not required_columns.issubset(df.columns):
        print(f"❌ Il manque une ou plusieurs colonnes : {required_columns - set(df.columns)}")
        return

    validated_contents = []

    for idx, row in df.iterrows():
        rule_code = row.get('generated_ansible_lint_rule')
        snippet_code = row.get('code_snippet')
        smell_category = str(row.get('smell_category')).strip().replace(" ", "").replace("/", "_")
        filepath = str(row.get('filepath')).strip() if pd.notna(row.get('filepath')) else ""

        rule_index = idx + 1
        security_id = f"SECURITY{rule_index:03d}"
        validated_rule_content = ""

        ### ----- Traitement de generated_ansible_lint_rule -----
        if pd.notna(rule_code) and smell_category:
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

                # Fichier de règle basé sur smell_category
                rule_filename = f"{smell_category}{rule_index}.py"
                rule_filepath = os.path.join(output_dir, rule_filename)

                with open(rule_filepath, 'w', encoding='utf-8') as f:
                    f.write(final_code)
                print(f"✅ Règle écrite dans {rule_filepath} avec id '{security_id}'")

        validated_contents.append(validated_rule_content)

        ### ----- Traitement de code_snippet -----
        if pd.notna(snippet_code):
            extension = ".yaml" if filepath.endswith(".yaml") or filepath.endswith(".yml") else ".py"
            test_filename = f"ansible_test{rule_index}{extension}"
            test_filepath = os.path.join(output_dir, test_filename)

            with open(test_filepath, 'w', encoding='utf-8') as f:
                f.write(str(snippet_code))
            print(f"✅ Snippet écrit dans {test_filename}")

    # Ajout de la colonne validated_rules contenant le code Python modifié
    df["validated_rules"] = validated_contents

    # Sauvegarde du nouveau fichier Excel
    df.to_excel(output_excel, index=False)
    print(f"\n📄 Nouveau fichier Excel généré : {output_excel}")



# Exemple d’utilisation
if __name__ == "__main__":
    fichier_excel = "ansible_dataset_llm_generated_rules.xlsx"  # Remplacer si besoin
    extract_rules_and_tests(fichier_excel)
