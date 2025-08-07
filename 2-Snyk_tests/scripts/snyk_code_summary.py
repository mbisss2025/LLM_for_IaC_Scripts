import json
import os
import pandas as pd

def extract_snyk_data_to_excel(json_folder_path, excel_output_path):
    """
    Extrait les données des fichiers JSON Snyk Code et les sauvegarde dans un fichier Excel.

    Args:
        json_folder_path (str): Le chemin d'accès au dossier contenant les fichiers JSON.
        excel_output_path (str): Le chemin d'accès pour sauvegarder le fichier Excel résultant.
    """
    all_results_data = []
    rules_data = {}

    # Parcourir tous les fichiers dans le dossier spécifié
    for filename in os.listdir(json_folder_path):
        if filename.endswith(".json"):
            file_path = os.path.join(json_folder_path, filename)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # Traiter chaque "run" dans le fichier JSON
                for run in data.get("runs", []):
                    # Extraire les informations sur les règles (rules)
                    tool_driver_rules = run.get("tool", {}).get("driver", {}).get("rules", [])
                    for rule in tool_driver_rules:
                        rule_id = rule.get("id")
                        if rule_id and rule_id not in rules_data:
                            rules_data[rule_id] = {
                                "rule_name": rule.get("name"),
                                "rule_short_description": rule.get("shortDescription", {}).get("text"),
                                "rule_help_markdown": rule.get("help", {}).get("markdown"),
                                "rule_level_default": rule.get("defaultConfiguration", {}).get("level"),
                                "rule_tags": ", ".join(rule.get("properties", {}).get("tags", [])),
                                "rule_categories": ", ".join(rule.get("properties", {}).get("categories", [])),
                                "rule_precision": rule.get("properties", {}).get("precision"),
                                "rule_cwe": ", ".join(rule.get("properties", {}).get("cwe", []))
                            }

                    # Extraire les résultats (results)
                    for result in run.get("results", []):
                        result_data = {}
                        result_data["original_filename"] = filename # Garder une trace du fichier source

                        # Informations de base du résultat
                        result_data["rule_id"] = result.get("ruleId")
                        result_data["rule_index"] = result.get("ruleIndex")
                        result_data["level"] = result.get("level")
                        result_data["message_text"] = result.get("message", {}).get("text")
                        result_data["message_markdown"] = result.get("message", {}).get("markdown")
                        result_data["arguments"] = ", ".join(result.get("message", {}).get("arguments", [])) # Convertir la liste en chaîne

                        # Informations de localisation (première localisation)
                        location = result.get("locations", [{}])[0].get("physicalLocation", {})
                        artifact_location = location.get("artifactLocation", {})
                        region = location.get("region", {})
                        result_data["location_uri"] = artifact_location.get("uri")
                        result_data["location_uri_base_id"] = artifact_location.get("uriBaseId")
                        result_data["location_start_line"] = region.get("startLine")
                        result_data["location_end_line"] = region.get("endLine")
                        result_data["location_start_column"] = region.get("startColumn")
                        result_data["location_end_column"] = region.get("endColumn")

                        # Empreintes (Fingerprints) - Concaténer les valeurs
                        fingerprints = result.get("fingerprints", {})
                        result_data["fingerprints"] = "; ".join([f"{k}: {v}" for k, v in fingerprints.items()])


                        # CodeFlows (simplifié pour la première location du premier threadFlow)
                        code_flow = result.get("codeFlows", [{}])[0].get("threadFlows", [{}])[0].get("locations", [{}])[0].get("location", {})
                        if code_flow: # Vérifier si code_flow n'est pas vide
                            cf_physical_location = code_flow.get("physicalLocation", {})
                            cf_artifact_location = cf_physical_location.get("artifactLocation", {})
                            cf_region = cf_physical_location.get("region", {})
                            result_data["codeflow_location_id"] = code_flow.get("id")
                            result_data["codeflow_uri"] = cf_artifact_location.get("uri")
                            result_data["codeflow_uri_base_id"] = cf_artifact_location.get("uriBaseId")
                            result_data["codeflow_start_line"] = cf_region.get("startLine")
                            result_data["codeflow_end_line"] = cf_region.get("endLine")
                            result_data["codeflow_start_column"] = cf_region.get("startColumn")
                            result_data["codeflow_end_column"] = cf_region.get("endColumn")


                        # Propriétés du résultat
                        properties = result.get("properties", {})
                        result_data["priority_score"] = properties.get("priorityScore")
                        # Extraire les facteurs de priorité sous forme de chaîne
                        priority_factors = []
                        for factor in properties.get("priorityScoreFactors", []):
                            priority_factors.append(f"label: {factor.get('label')}, type: {factor.get('type')}")
                        result_data["priority_score_factors"] = "; ".join(priority_factors)
                        result_data["is_autofixable"] = properties.get("isAutofixable")

                        # Ajouter les informations de la règle correspondante
                        if result_data["rule_id"] in rules_data:
                            result_data.update(rules_data[result_data["rule_id"]])

                        all_results_data.append(result_data)

            except json.JSONDecodeError:
                print(f"Erreur de décodage JSON pour le fichier : {filename}. Ce fichier sera ignoré.")
            except Exception as e:
                print(f"Une erreur est survenue lors du traitement du fichier {filename}: {e}")

    # Créer un DataFrame Pandas
    df = pd.DataFrame(all_results_data)

    # Réorganiser les colonnes pour une meilleure lisibilité (optionnel)
    # Vous pouvez personnaliser l'ordre ici
    column_order = [
        "original_filename", "rule_id", "rule_name", "level", "message_text",
        "location_uri", "location_start_line", "location_end_line",
        "priority_score", "is_autofixable", "rule_short_description",
        "rule_cwe", "rule_tags", "rule_categories",
        # Ajoutez d'autres colonnes si nécessaire, par exemple :
        "message_markdown", "arguments", "location_uri_base_id",
        "location_start_column", "location_end_column", "fingerprints",
        "codeflow_location_id", "codeflow_uri", "codeflow_uri_base_id",
        "codeflow_start_line", "codeflow_end_line", "codeflow_start_column",
        "codeflow_end_column", "priority_score_factors", "rule_help_markdown",
        "rule_level_default", "rule_precision"
    ]
    # Filtrer pour n'inclure que les colonnes présentes dans le DataFrame
    df = df.reindex(columns=[col for col in column_order if col in df.columns])


    # Sauvegarder le DataFrame dans un fichier Excel
    try:
        df.to_excel(excel_output_path, index=False, sheet_name='Snyk Code Results')
        print(f"Les données ont été exportées avec succès vers {excel_output_path}")
    except Exception as e:
        print(f"Erreur lors de la sauvegarde du fichier Excel : {e}")

# --- Configuration ---
# REMPLACEZ CES VALEURS PAR VOS CHEMINS
dossier_json = r"C:\\Users\\DELL\\Documents\\test_snyk\\test-saltstack\\salt" # Ou le chemin complet vers votre dossier, ex: "/chemin/vers/vos/fichiers/json"
fichier_excel_sortie = r"C:\\Users\\DELL\\Documents\\test_snyk\\test-saltstack\\snykanalyse\\snyk_code_results_dossier_salt.xlsx"
# --------------------

# Exécuter la fonction
extract_snyk_data_to_excel(dossier_json, fichier_excel_sortie)