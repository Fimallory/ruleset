import requests
import json
import sys
import ipaddress
import shutil
import subprocess
import os
from pathlib import Path

# --- Configuration ---
RULE_CONFIG = {
    "PRIVATE": [
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/private.txt"
    ],
    "CNCIDR": [
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/cncidr.txt"
    ],
    "DIRECT": [
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/direct.txt"
    ],
    "REJECT": [
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/reject.txt"
    ],
    "PROXY": [
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/proxy.txt"
    ],
    "GOOGLE": [
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/google.txt"
    ],
    "APPLE": [
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/apple.txt"
    ]
}

# Directory to save files
OUTPUT_DIR = Path("dist")

# Command line tools
CMD_SINGBOX = "sing-box"
CMD_MIHOMO = "mihomo"

def check_tool(tool_name):
    """Check if a CLI tool exists in the system PATH."""
    return shutil.which(tool_name) is not None

def is_ip_cidr(text):
    """Check if a string is a valid IP CIDR."""
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        return False

def parse_rules(group_name, urls):
    """
    Downloads and parses rules into a generic list of (type, value) tuples.
    """
    print(f"[*] Processing group: {group_name}")
    raw_rules = [] # List of tuples: (rule_type, value)

    for url in urls:
        print(f"  - Downloading from {url}")
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"  [!] Error: Failed to download {url}. {e}")
            continue

        lines = response.text.splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if '//' in line:
                line = line.split('//')[0].strip()

            rule_type = "UNKNOWN"
            value = ""

            if ',' in line:
                try:
                    parts = line.split(',')
                    rule_type = parts[0].strip().upper()
                    value = parts[1].strip()
                    if rule_type == 'IP-CIDR6':
                        rule_type = 'IP-CIDR'
                except IndexError:
                    continue
            else:
                if is_ip_cidr(line):
                    rule_type = 'IP-CIDR'
                    value = line
                else:
                    rule_type = 'DOMAIN-SUFFIX' 
                    value = line
            
            if value:
                raw_rules.append((rule_type, value))

    print(f"  -> Parsed {len(raw_rules)} raw rules.")
    return raw_rules

def detect_rule_type(raw_rules):
    """
    Detects if the ruleset is 'domain' or 'ip' based on content.
    Used for Mihomo compilation.
    """
    # If there is ANY domain rule, treat as domain (mixed is usually handled as domain behavior)
    for r_type, _ in raw_rules:
        if r_type.startswith('DOMAIN'):
            return 'domain'
    
    # If no domains found, assume it's an IP list (like CNCIDR)
    return 'ip'

def generate_singbox_json(raw_rules, output_path):
    """
    Converts raw rules to Sing-box Source JSON format.
    """
    sb_rules = []
    
    domain = []
    domain_suffix = []
    domain_keyword = []
    ip_cidr = []
    
    for r_type, val in raw_rules:
        if r_type == 'DOMAIN':
            domain.append(val)
        elif r_type == 'DOMAIN-SUFFIX':
            domain_suffix.append(val)
        elif r_type == 'DOMAIN-KEYWORD':
            domain_keyword.append(val)
        elif r_type == 'IP-CIDR':
            ip_cidr.append(val)
    
    rule_obj = {}
    if domain: rule_obj["domain"] = domain
    if domain_suffix: rule_obj["domain_suffix"] = domain_suffix
    if domain_keyword: rule_obj["domain_keyword"] = domain_keyword
    if ip_cidr: rule_obj["ip_cidr"] = ip_cidr
    
    if rule_obj:
        sb_rules.append(rule_obj)

    final_json = {
        "version": 1,
        "rules": sb_rules
    }

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(final_json, f, indent=2)
        return True
    except IOError as e:
        print(f"  [!] Error writing JSON {output_path}: {e}")
        return False

def generate_mihomo_yaml(raw_rules, output_path):
    """
    Converts raw rules to Mihomo/Clash YAML payload format.
    """
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for r_type, val in raw_rules:
                f.write(f"  - {r_type},{val}\n")
        return True
    except IOError as e:
        print(f"  [!] Error writing YAML {output_path}: {e}")
        return False

def compile_srs(json_path, srs_path):
    """Run sing-box to compile JSON to SRS."""
    print(f"  -> Compiling SRS: {srs_path.name}")
    try:
        subprocess.run(
            [CMD_SINGBOX, "rule-set", "compile", "--output", str(srs_path), str(json_path)],
            check=True,
            capture_output=True
        )
        # Check for 0-byte file
        if srs_path.exists() and srs_path.stat().st_size == 0:
            print(f"     [!] Generated SRS is empty. Deleting.")
            srs_path.unlink()
        else:
            print("     [OK] SRS Compiled.")
    except subprocess.CalledProcessError as e:
        print(f"     [!] SRS Compilation failed: {e}")

def compile_mrs(yaml_path, mrs_path, rule_type):
    """Run mihomo to compile YAML to MRS."""
    print(f"  -> Compiling MRS: {mrs_path.name} (Type: {rule_type})")
    try:
        # mihomo convert-ruleset <type> <input> <output>
        subprocess.run(
            [CMD_MIHOMO, "convert-ruleset", rule_type, "yaml", str(yaml_path), str(mrs_path)],
            check=True,
            capture_output=True
        )
        
        # Check for 0-byte file
        if mrs_path.exists() and mrs_path.stat().st_size == 0:
            print(f"     [!] Generated MRS is empty. Deleting.")
            mrs_path.unlink()
        else:
            print("     [OK] MRS Compiled.")
            
    except subprocess.CalledProcessError as e:
        print(f"     [!] MRS Compilation failed: {e}")


def main():
    if not OUTPUT_DIR.exists():
        OUTPUT_DIR.mkdir()

    can_compile_srs = check_tool(CMD_SINGBOX)
    can_compile_mrs = check_tool(CMD_MIHOMO)
    
    if not can_compile_srs:
        print("[-] 'sing-box' not found. SRS skipped.")
    if not can_compile_mrs:
        print("[-] 'mihomo' not found. MRS skipped.")

    print("-" * 40)

    for group_name, urls in RULE_CONFIG.items():
        # 1. Parse
        raw_rules = parse_rules(group_name, urls)
        if not raw_rules:
            continue
        
        # File Paths
        json_path = OUTPUT_DIR / f"{group_name}.json"
        srs_path = OUTPUT_DIR / f"{group_name}.srs"
        yaml_path = OUTPUT_DIR / f"{group_name}.yaml"
        mrs_path = OUTPUT_DIR / f"{group_name}.mrs"

        # 2. Generate Sing-box JSON & SRS
        if generate_singbox_json(raw_rules, json_path):
            print(f"  -> JSON Source saved: {json_path.name}")
            if can_compile_srs:
                compile_srs(json_path, srs_path)

        # 3. Generate Mihomo YAML & MRS
        if generate_mihomo_yaml(raw_rules, yaml_path):
            if can_compile_mrs:
                # Detect type: 'ip' for CNCIDR, 'domain' for others
                r_type = detect_rule_type(raw_rules)
                compile_mrs(yaml_path, mrs_path, classic)
            
            # Remove intermediate YAML to keep dist folder clean (Optional)
            # yaml_path.unlink(missing_ok=True) 

        print("-" * 40)

if __name__ == "__main__":
    main()
