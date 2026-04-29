"""
Installed Software Scanner
Scans Windows registry at startup. Writes to SOC/Config/installed_software.json
for use by both the Intel pipeline (CVE severity gating) and SOC engine (Phase 2B).
"""

import winreg
import json
import os
from datetime import datetime, timezone

SOC_CONFIG_PATH = os.path.join(os.environ["USERPROFILE"], "Desktop", "SOC", "Config")
OUTPUT_FILE     = os.path.join(SOC_CONFIG_PATH, "installed_software.json")

UNINSTALL_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]


def _read_subkeys(hive, path):
    entries = []
    try:
        key = winreg.OpenKey(hive, path)
    except OSError:
        return entries

    i = 0
    while True:
        try:
            subkey_name = winreg.EnumKey(key, i)
            i += 1
        except OSError:
            break
        try:
            subkey = winreg.OpenKey(key, subkey_name)

            def _get(field):
                try:
                    val, _ = winreg.QueryValueEx(subkey, field)
                    return str(val).strip()
                except OSError:
                    return ""

            name      = _get("DisplayName")
            publisher = _get("Publisher")
            version   = _get("DisplayVersion")

            if name:
                entries.append({"name": name, "publisher": publisher, "version": version})

            winreg.CloseKey(subkey)
        except OSError:
            pass

    winreg.CloseKey(key)
    return entries


def scan_installed_software():
    """
    Scan Windows registry for installed software.
    Deduplicates on (name, publisher). Writes JSON to SOC Config dir.
    Returns the software list.
    """
    seen     = set()
    software = []

    for hive, path in UNINSTALL_PATHS:
        for entry in _read_subkeys(hive, path):
            key = (entry["name"].lower(), entry["publisher"].lower())
            if key in seen:
                continue
            seen.add(key)
            software.append(entry)

    software.sort(key=lambda x: x["name"].lower())

    output = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "count":      len(software),
        "software":   software,
    }

    os.makedirs(SOC_CONFIG_PATH, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"[Scanner] {len(software)} entries written to {OUTPUT_FILE}")
    return software


if __name__ == "__main__":
    scan_installed_software()
