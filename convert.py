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

# Command line tools (ensure these are in your system PATH)
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
            response = requests.get(url, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"  [!] Error: Failed to download {url}. {e}")
            continue

        lines = response.text.splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Handle comments inside lines (rare in raw lists but possible)
            if '//' in line:
                line = line.split('//')[0].strip()

            rule_type = "UNKNOWN"
            value = ""

            if ',' in line:
                try:
                    parts = line.split(',')
                    rule_type = parts[0].strip().upper()
                    value = parts[1].strip()
                    
                    # Normalization
                    if rule_type == 'IP-CIDR6':
                        rule_type = 'IP-CIDR'
                except IndexError:
                    continue
            else:
                # Handle raw lists (IPs or Domains without type prefix)
                if is_ip_cidr(line):
                    rule_type = 'IP-CIDR'
                    value = line
                else:
                    rule_type = 'DOMAIN-SUFFIX' # Default assumption for bare lists
                    value = line
            
            if value:
                raw_rules.append((rule_type, value))

    print(f"  -> Parsed {len(raw_rules)} raw rules.")
    return raw_rules

def generate_singbox_json(raw_rules, output_path):
    """
    Converts raw rules to Sing-box Source JSON format.
    Optimized to use arrays for smaller file size.
    """
    sb_rules = []
    
    # Buckets for grouping
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
    
    # Construct rule object
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
                # Mihomo uses 'DOMAN-SUFFIX,google.com' etc directly in payload
                # Map IP-CIDR to just IP-CIDR (Mihomo handles v4/v6 auto)
                f.write(f"  - {r_type},{val}\n")
        return True
    except IOError as e:
        print(f"  [!] Error writing YAML {output_path}: {e}")
        return False

def compile_srs(json_path, srs_path):
    """Run sing-box to compile JSON to SRS."""
    if not check_tool(CMD_SINGBOX):
        print("  [!] 'sing-box' command not found. Skipping SRS compilation.")
        return

    print(f"  -> Compiling SRS: {srs_path.name}")
    try:
        subprocess.run(
            [CMD_SINGBOX, "rule-set", "compile", "--output", str(srs_path), str(json_path)],
            check=True,
            capture_output=True
        )
        print("     [OK] SRS Compiled.")
    except subprocess.CalledProcessError as e:
        print(f"     [!] SRS Compilation failed: {e}")

def compile_mrs(yaml_path, mrs_path):
    """Run mihomo to compile YAML to MRS."""
    if not check_tool(CMD_MIHOMO):
        print("  [!] 'mihomo' command not found. Skipping MRS compilation.")
        return

    print(f"  -> Compiling MRS: {mrs_path.name}")
    try:
        # Mihomo compilation command: mihomo convert-ruleset <type> <input> <output>
        # However, since files can contain mixed Domain/IP, we rely on Mihomo's ability to handle source.
        # But 'convert-ruleset' usually requires type 'domain' or 'ip'.
        # We try 'domain' as it is generic enough for modern Meta or just pass source.
        # Actually, best practice is to output both or let mihomo detect.
        # Standard command: mihomo convert-ruleset domain/ip yaml input.yaml output.mrs
        
        # NOTE: If your ruleset mixes IP and Domain, compilation might warn or fail depending on version.
        # We will use 'domain' type as it's the most common container, or rely on auto-detection if tool allows.
        
        subprocess.run(
            [CMD_MIHOMO, "convert-ruleset", "domain", "yaml", str(yaml_path), str(mrs_path)],
            check=True,
            capture_output=True
        )
        print("     [OK] MRS Compiled.")
    except subprocess.CalledProcessError as e:
        # Fallback: try 'ip' if domain failed, or it might be mixed content issue
        print(f"     [!] MRS Compilation failed (Check if mihomo installed or syntax): {e}")


def main():
    if not OUTPUT_DIR.exists():
        OUTPUT_DIR.mkdir()

    # Determine if we can compile
    can_compile_srs = check_tool(CMD_SINGBOX)
    can_compile_mrs = check_tool(CMD_MIHOMO)
    
    if not can_compile_srs:
        print("[-] 'sing-box' not found in PATH. Only .json will be generated, .srs skipped.")
    if not can_compile_mrs:
        print("[-] 'mihomo' not found in PATH. Only .yaml will be generated, .mrs skipped.")

    print("-" * 40)

    for group_name, urls in RULE_CONFIG.items():
        # 1. Parse
        raw_rules = parse_rules(group_name, urls)
        if not raw_rules:
            continue
        
        # File Paths
        json_path = OUTPUT_DIR / f"{group_name}.json"
        srs_path = OUTPUT_DIR / f"{group_name}.srs"
        yaml_path = OUTPUT_DIR / f"{group_name}.yaml" # Intermediate for MRS
        mrs_path = OUTPUT_DIR / f"{group_name}.mrs"

        # 2. Generate Sing-box JSON
        if generate_singbox_json(raw_rules, json_path):
            print(f"  -> JSON Source saved: {json_path.name}")
            # 3. Compile SRS
            if can_compile_srs:
                compile_srs(json_path, srs_path)

        # 4. Generate Mihomo YAML
        if generate_mihomo_yaml(raw_rules, yaml_path):
            # print(f"  -> YAML Source saved: {yaml_path.name}") # Optional log
            # 5. Compile MRS
            if can_compile_mrs:
                compile_mrs(yaml_path, mrs_path)
            
            # Cleanup intermediate YAML if you want, but keeping it is good for debugging
            # yaml_path.unlink(missing_ok=True) 

        print("-" * 40)

if __name__ == "__main__":
    main()
