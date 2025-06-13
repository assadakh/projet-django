import re
import json


def parse_nmap_output(output_lines):
    """
    Parse la sortie Nmap pour extraire les ports ouverts avec leurs services.
    Renvoie une liste de dicts : [{"port": "80/tcp", "state": "open", "service": "http"}, ...]
    """
    results = []
    port_section = False

    for line in output_lines:
        # Détecte le début de la section des ports
        if re.match(r"PORT\s+STATE\s+SERVICE", line):
            port_section = True
            continue
        if port_section:
            if line.strip() == "":
                # Fin de la section ports
                break
            parts = line.split()
            if len(parts) >= 3:
                results.append({
                    "port": parts[0],
                    "state": parts[1],
                    "service": parts[2]
                })
    return results



def parse_whatweb_output(output_lines):
    """
    Parse la sortie WhatWeb pour extraire les technologies détectées.
    """
    results = []
    # Expression régulière : TechName[Version]
    pattern = re.compile(r'(\S+)\[([^\]]+)\]')

    for line in output_lines:
        matches = pattern.findall(line)
        for tech, version in matches:
            results.append(f"{tech}[{version}]")
    return results



def parse_json_output(output_str):
    """
    Parse une chaîne JSON et retourne les alerts ou un message d'erreur.
    """
    try:
        data_json = json.loads(output_str)
        alerts = data_json.get("alerts", [])
    except json.JSONDecodeError as e:
        alerts = [{"alert": "Erreur de parsing JSON", "description": str(e)}]
    return alerts
