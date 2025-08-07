import json
import os
import pandas as pd

def extract_snyk_iac_data_to_excel_updated(json_folder_path, excel_output_path):
    """
    Extrait les données des fichiers JSON Snyk IaC (basé sur la structure de snyk-iac-camunda-cd9f8c7.json)
    et les sauvegarde dans un fichier Excel.

    Args:
        json_folder_path (str): Le chemin d'accès au dossier contenant les fichiers JSON.
        excel_output_path (str): Le chemin d'accès pour sauvegarder le fichier Excel résultant.
    """
    all_issues_data = []

    for filename in os.listdir(json_folder_path):
        if filename.endswith(".json"):
            file_path = os.path.join(json_folder_path, filename)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                if isinstance(data, dict) and data.get("ok") is False and "error" in data:
                    print(f"Fichier '{filename}' est un message d'erreur Snyk et sera ignoré: {data.get('error')}")
                    continue

                project_results = []
                if isinstance(data, list): # Cas de votre fichier snyk-iac-camunda-cd9f8c7.json
                    project_results.extend(data)
                elif isinstance(data, dict): # Cas d'un seul "projet"
                    project_results.append(data)
                else:
                    print(f"Format JSON inattendu dans '{filename}'. Fichier ignoré.")
                    continue

                for project_result in project_results:
                    # Informations au niveau du "projet" (chaque élément de la liste JSON)
                    project_name = project_result.get("projectName", "N/A")
                    # Utiliser displayTargetFile si disponible, sinon targetFile
                    target_file_val = project_result.get("targetFile", "N/A")
                    display_target_file = project_result.get("displayTargetFile", target_file_val)
                    target_file_path_val = project_result.get("targetFilePath", "N/A")
                    package_manager_val = project_result.get("packageManager", "N/A")
                    project_path_val = project_result.get("path", "N/A") # Chemin du répertoire scanné
                    project_type_val = project_result.get("projectType", package_manager_val) # projectType ou packageManager
                    org_val = project_result.get("org", "N/A")
                    meta_org_public_id = project_result.get("meta", {}).get("orgPublicId", "N/A")
                    is_ok = project_result.get("ok") # Peut être True/False

                    # Clé contenant les problèmes dans votre exemple
                    issues_list_key = "infrastructureAsCodeIssues"

                    if issues_list_key not in project_result or not isinstance(project_result[issues_list_key], list):
                        # Si le fichier n'a pas de problèmes listés ou si la clé est absente, on peut quand même
                        # enregistrer une ligne pour indiquer que le fichier a été scanné, si souhaité,
                        # ou simplement l'ignorer s'il n'y a pas d'issues.
                        # Pour l'instant, on l'ignore s'il n'y a pas d'issues à rapporter.
                        if project_result.get(issues_list_key) == []: # Explicitly empty list
                             print(f"Aucun '{issues_list_key}' trouvé pour '{display_target_file}' dans '{filename}'.")
                        # else:
                        #     print(f"Structure inattendue (manque '{issues_list_key}') pour '{display_target_file}' dans '{filename}'.")
                        continue


                    for issue in project_result.get(issues_list_key, []):
                        issue_data = {}
                        issue_data["original_json_filename"] = filename
                        issue_data["project_name"] = project_name
                        issue_data["target_file"] = display_target_file
                        issue_data["target_file_path"] = target_file_path_val
                        issue_data["iac_type"] = project_type_val # Ou package_manager_val
                        issue_data["scan_path"] = project_path_val
                        issue_data["snyk_org"] = org_val
                        issue_data["snyk_org_id"] = meta_org_public_id
                        issue_data["scan_ok_status"] = is_ok

                        issue_data["issue_id"] = issue.get("id")
                        issue_data["public_id"] = issue.get("publicId")
                        issue_data["title"] = issue.get("title")
                        issue_data["severity"] = issue.get("severity")
                        issue_data["is_ignored"] = issue.get("isIgnored")
                        issue_data["sub_type"] = issue.get("subType") # Ex: "ClusterRole", "Pod"
                        issue_data["documentation_url"] = issue.get("documentation")
                        issue_data["is_custom_rule"] = issue.get("isGeneratedByCustomRule")
                        issue_data["line_number"] = issue.get("lineNumber")

                        # Utiliser les champs de iacDescription s'ils sont plus complets, sinon les champs directs
                        iac_desc = issue.get("iacDescription", {})
                        issue_data["description"] = iac_desc.get("issue") if iac_desc.get("issue") else issue.get("issue")
                        issue_data["impact"] = iac_desc.get("impact") if iac_desc.get("impact") else issue.get("impact")
                        issue_data["resolve_suggestion"] = iac_desc.get("resolve") if iac_desc.get("resolve") else issue.get("resolve")

                        issue_data["detailed_message"] = issue.get("msg") # Chemin technique ou message complémentaire

                        # Extraction de 'path' de l'issue (chemin dans le fichier IaC)
                        config_path_list = issue.get("path", [])
                        issue_data["config_path_in_file"] = " -> ".join(map(str, config_path_list)) if config_path_list else "N/A"

                        # Remédiation
                        remediation = issue.get("remediation", {})
                        if isinstance(remediation, dict):
                            for lang, code in remediation.items():
                                issue_data[f"remediation_{lang}"] = code
                        elif remediation:
                            issue_data["remediation_general"] = str(remediation)

                        # Références
                        references_list = issue.get("references", [])
                        issue_data["references"] = ", ".join(references_list) if references_list else "N/A"

                        # Compliance
                        compliance_list = issue.get("compliance", []) # Semble être toujours vide dans l'exemple
                        issue_data["compliance"] = ", ".join(map(str, compliance_list)) if compliance_list else "N/A"


                        all_issues_data.append(issue_data)

            except json.JSONDecodeError:
                print(f"Erreur de décodage JSON pour le fichier : '{filename}'. Ce fichier sera ignoré.")
            except Exception as e:
                print(f"Une erreur est survenue lors du traitement du fichier '{filename}': {e}")

    if not all_issues_data:
        print("Aucune donnée Snyk IaC n'a été extraite. Le fichier Excel ne sera pas créé.")
        return

    df = pd.DataFrame(all_issues_data)

    # Définir un ordre de colonnes de base
    column_order = [
        "original_json_filename", "project_name", "target_file", "target_file_path",
        "iac_type", "scan_path", "snyk_org", "snyk_org_id", "scan_ok_status",
        "issue_id", "public_id", "title", "severity", "line_number",
        "description", "impact", "resolve_suggestion", "detailed_message",
        "config_path_in_file", "references", "sub_type", "is_ignored", "is_custom_rule",
        "compliance" # Ajoutez d'autres colonnes de base si nécessaire
    ]
    # Ajouter dynamiquement les colonnes de remédiation
    remediation_cols = sorted([col for col in df.columns if col.startswith("remediation_")])
    final_column_order = [col for col in column_order if col in df.columns] # Garder l'ordre défini
    # Ajouter les colonnes de remédiation à la fin
    for col in remediation_cols:
        if col not in final_column_order:
            final_column_order.append(col)
    # S'assurer que toutes les autres colonnes du df sont incluses, même si non listées explicitement
    for col in df.columns:
        if col not in final_column_order:
            final_column_order.append(col) # Les ajouter à la fin

    df = df.reindex(columns=final_column_order)

    try:
        df.to_excel(excel_output_path, index=False, sheet_name='Snyk IaC Results')
        print(f"Les données Snyk IaC ont été exportées avec succès vers '{excel_output_path}'")
    except Exception as e:
        print(f"Erreur lors de la sauvegarde du fichier Excel : {e}")

# --- Configuration ---
dossier_json_iac = "."  # MODIFIEZ CECI : Chemin vers votre dossier de fichiers JSON IaC
fichier_excel_sortie_iac = "." # Nom du fichier Excel de sortie
# --------------------

if __name__ == "__main__":
    # Pour tester, assurez-vous que 'dossier_json_iac' pointe vers un dossier
    # contenant votre fichier 'snyk-iac-camunda-cd9f8c7.json'
    # et potentiellement d'autres fichiers JSON Snyk IaC.

    # Exemple : si vos fichiers sont dans un sous-dossier 'iac_reports'
    # dossier_json_iac = "iac_reports"

    extract_snyk_iac_data_to_excel_updated(dossier_json_iac, fichier_excel_sortie_iac)