#!/usr/bin/env python3
"""
AegisCloud — ATT&CK Navigator Layer Generator

Takes your manually-filled-in detection coverage (see
docs/attack-coverage-data.json) and produces a JSON layer file you can
upload directly to https://mitre-attack.github.io/attack-navigator/ for a
visual, color-coded map of which MITRE ATT&CK techniques your platform
detects, which it doesn't, and which it actively prevents.

This is one of the strongest single artifacts you can put in a portfolio
or bring to an interview — it's the industry-standard way security teams
communicate detection coverage, and building one yourself (rather than
just listing tools you configured) is a genuine differentiator.

Usage:
    python3 generate-attack-navigator-layer.py

Reads: docs/attack-coverage-data.json (edit this file with your real
       results after running scripts/run-stratus-attacks.sh and manually
       checking GuardDuty/Security Hub/CloudWatch Logs)
Writes: aegiscloud-attack-navigator-layer.json
"""

import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_PATH = os.path.join(SCRIPT_DIR, "..", "docs", "attack-coverage-data.json")
OUTPUT_PATH = os.path.join(SCRIPT_DIR, "..", "aegiscloud-attack-navigator-layer.json")

# Color coding: green = prevented (the attack couldn't even succeed, e.g.
# blocked by a permission boundary), yellow = detected (attack succeeded
# but a finding fired), red = gap (attack succeeded, nothing fired).
COLOR_MAP = {
    "prevented": "#2ecc71",
    "detected": "#f1c40f",
    "gap": "#e74c3c",
}


def main():
    with open(INPUT_PATH) as f:
        coverage_data = json.load(f)

    layer = {
        "name": "AegisCloud Detection Coverage",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            "Detection/prevention coverage map built from adversary emulation "
            "against the AegisCloud single-account platform using Stratus Red Team, "
            "cross-referenced against GuardDuty, Security Hub, and custom "
            "remediation Lambda logs."
        ),
        "techniques": [],
        "gradient": {
            "colors": ["#e74c3c", "#f1c40f", "#2ecc71"],
            "minValue": 0,
            "maxValue": 1,
        },
        "legendItems": [
            {"label": "Prevented (blocked before completion)", "color": COLOR_MAP["prevented"]},
            {"label": "Detected (attack succeeded, finding fired)", "color": COLOR_MAP["detected"]},
            {"label": "Gap (attack succeeded, no detection)", "color": COLOR_MAP["gap"]},
        ],
    }

    for entry in coverage_data:
        layer["techniques"].append({
            "techniqueID": entry["attack_technique_id"],
            "color": COLOR_MAP[entry["status"]],
            "comment": (
                f"Stratus technique: {entry['stratus_technique']}. "
                f"Detection source: {entry.get('detection_source', 'none')}. "
                f"{entry.get('notes', '')}"
            ),
            "enabled": True,
        })

    with open(OUTPUT_PATH, "w") as f:
        json.dump(layer, f, indent=2)

    print(f"Layer written to {OUTPUT_PATH}")
    print("Upload this file at https://mitre-attack.github.io/attack-navigator/ "
          "(Open Existing Layer -> Upload from Local) to view it visually.")


if __name__ == "__main__":
    main()
