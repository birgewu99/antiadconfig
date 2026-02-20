#!/usr/bin/env python3
import yaml
import requests
from datetime import datetime
import os
from collections import defaultdict

HEADER = """# Shadowrocket: {datetime}
[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4
dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query, tls://223.5.5.5, tls://119.29.29.29, tls://223.6.6.6,tls://119.28.28.28, 2400:3200::1,2402:4e00::
fallback-dns-server = 223.5.5.5, 223.6.6.6, 119.29.29.29, 119.28.28.28,2400:3200::2,2402:4e00:8000::,system
ipv6 = false
prefer-ipv6 = false
dns-direct-system = true
icmp-auto-reply = true
always-reject-url-rewrite = true
private-ip-answer = true
dns-direct-fallback-proxy = false
udp-policy-not-supported-behaviour = REJECT
use-local-host-item-for-proxy = false
quic-block = all

[Rule]
"""

FOOTER = """
[Host]
localhost = 127.0.0.1

[URL Rewrite]
^https?://(www.)?g.cn($|/.*) https://www.google.com$2 302
^https?://(www.)?google.cn($|/.*) https://www.google.com$2 302
"""

IP_CIDR_KEYWORDS = ["lancidr", "cncidr", "telegramcidr"]

def fetch_rules(url):
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        lines = resp.text.strip().splitlines()
        return [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []

def parse_rule(rule_lines, policy="REJECT-200", is_ip=False):
    """
    解析 RULE-SET
    自动识别：
    1. 纯域名列表
    2. 纯 IP 列表
    3. 已带规则前缀的 Clash/Shadowrocket 格式
    """
    lines = []

    for rule in rule_lines:
        rule = rule.strip().strip("- '\"")

        if not rule or rule.startswith('#') or rule == 'payload:':
            continue

        # ===== 已经带规则类型的情况 =====
        if ',' in rule:
            parts = rule.split(',', 1)
            rule_type = parts[0].upper()

            # 这些是标准规则类型
            if rule_type in [
                "DOMAIN",
                "DOMAIN-SUFFIX",
                "DOMAIN-KEYWORD",
                "IP-CIDR",
                "IP-CIDR6",
                "GEOIP",
                "DST-PORT",
                "SRC-IP-CIDR",
                "PROCESS-NAME",
                "PROTOCOL"
            ]:
                lines.append(f"{rule},{policy}")
                continue

        # ===== IP 列表（telegramcidr 那种）=====
        if is_ip:
            lines.append(f"IP-CIDR,{rule},{policy}")
            continue

        # ===== 纯域名列表（loyalsoldier 那种）=====
        if rule.startswith('+.'):
            domain = rule[2:]
        elif rule.startswith('.'):
            domain = rule[1:]
        else:
            domain = rule

        lines.append(f"DOMAIN-SUFFIX,{domain},{policy}")

    return lines


def generate_rules():
    # containers
    ruleset_rules_by_policy = defaultdict(list)  # policy -> list of lines (from RULE-SET)
    explicit_domains = []  # list of tuples (type, value, policy) preserving order for hardcoded entries
    explicit_by_policy = defaultdict(list)  # policy -> list of explicit domain lines
    geoip_rules = []
    final_rule = None
    other_rules_by_policy = defaultdict(list)  # e.g., other non-RULE-SET sources with values

    with open('sources.yaml', 'r') as f:
        config = yaml.safe_load(f)

    # First pass: collect explicit (hardcoded) DOMAIN/DOMAIN-SUFFIX entries and process RULE-SET sources
    hardcoded_values = []  # list of domain strings (lower) preserving order
    for source in config.get('rules', []):
        stype = source.get('type', '').upper()
        policy = (source.get('policy', '') or "").upper() or "REJECT-200"

        if stype in ('DOMAIN-SUFFIX', 'DOMAIN'):
            value = source.get('value')
            if value:
                entry_type = 'DOMAIN' if stype == 'DOMAIN' else 'DOMAIN-SUFFIX'
                explicit_domains.append((entry_type, value, policy))
                explicit_by_policy[policy].append(f"{entry_type},{value},{policy}")
                hardcoded_values.append(value.lower())
                print(f"Added explicit {entry_type}: {value} with policy {policy}")
        elif stype == 'RULE-SET' and source.get('url'):
            url = source.get('url')
            print(f"Fetching {url} ...")
            rule_lines = fetch_rules(url)
            is_ip = any(k in url.lower() for k in IP_CIDR_KEYWORDS)
            parsed = parse_rule(rule_lines, policy=policy, is_ip=is_ip)

            # ===== 第二层去重：硬编码优先覆盖 RULE-SET =====
            filtered = []
            for line in parsed:
                # 处理 DOMAIN-SUFFIX, DOMAIN, DOMAIN-KEYWORD, IP-CIDR
                if line.startswith(("DOMAIN-SUFFIX,", "DOMAIN,", "DOMAIN-KEYWORD,", "IP-CIDR,")):
                    parts = line.split(',', 2)
                    value = parts[1].lower()
                    skip = False
                    for hc in hardcoded_values:
                        # DOMAIN 系列：等于或子域跳过
                        if parts[0].startswith("DOMAIN") and (value == hc or value.endswith('.' + hc)):
                            skip = True
                            break
                        # IP-CIDR：完全匹配跳过
                        elif parts[0] == "IP-CIDR" and value == hc:
                            skip = True
                            break
                    if skip:
                        continue
                filtered.append(line)

            ruleset_rules_by_policy[policy].extend(filtered)
            print(f"  Added {len(filtered)} rules from {url} ({'IP-CIDR' if is_ip else 'DOMAIN-SUFFIX'}) with policy {policy}")
        elif stype == 'GEOIP':
            country = source.get('country', '').upper()
            geoip_rules.append(f"GEOIP,{country},{policy}")
            print(f"Added GEOIP rule: GEOIP,{country},{policy}")
        elif stype == 'FINAL':
            final_rule = f"FINAL,{policy}" if policy else "FINAL,PROXY"
            print(f"Added FINAL rule: {final_rule}")
        else:
            value = source.get('value')
            if value:
                other_line = f"{stype},{value},{policy}"
                other_rules_by_policy[policy].append(other_line)
                print(f"Added other rule with value: {other_line}")
            else:
                other_line = f"{stype},{policy}"
                other_rules_by_policy[policy].append(other_line)
                print(f"Added other rule: {other_line}")

    # Now assemble output in order:
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "sr_rules.conf")
    written = set()  # 全局写入去重

    with open(output_file, 'w', encoding='utf-8') as f:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(HEADER.format(datetime=now))

        # ===== 优先级最高规则 =====
        quic_block_rule = "AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT-NO-DROP"
        if quic_block_rule not in written:
            f.write(quic_block_rule + '\n')
            written.add(quic_block_rule)

        # 0) RULE-SET REJECT-200
        reject_lines = ruleset_rules_by_policy.get("REJECT-200", [])
        for line in reject_lines:
            if line not in written:
                f.write(line + '\n')
                written.add(line)
                
        # 1) OTHER rules
        for policy, lines in other_rules_by_policy.items():
            for line in lines:
                if line not in written:
                    f.write(line + '\n')
                    written.add(line)

        # 2) PROXY: explicit hardcoded PROXYs first
        for entry_type, value, policy in explicit_domains:
            if policy == "PROXY":
                line = f"{entry_type},{value},{policy}"
                if line not in written:
                    f.write(line + '\n')
                    written.add(line)

        for line in explicit_by_policy.get("PROXY", []):
            if line not in written:
                f.write(line + '\n')
                written.add(line)

        for line in other_rules_by_policy.get("PROXY", []):
            if line not in written:
                f.write(line + '\n')
                written.add(line)

        for line in ruleset_rules_by_policy.get("PROXY", []):
            if line not in written:
                f.write(line + '\n')
                written.add(line)

        # 3) DIRECT
        for line in explicit_by_policy.get("DIRECT", []):
            if line not in written:
                f.write(line + '\n')
                written.add(line)

        for line in other_rules_by_policy.get("DIRECT", []):
            if line not in written:
                f.write(line + '\n')
                written.add(line)

        for line in ruleset_rules_by_policy.get("DIRECT", []):
            if line not in written:
                f.write(line + '\n')
                written.add(line)

        # 4) GEOIP
        for line in geoip_rules:
            if line not in written:
                f.write(line + '\n')
                written.add(line)

        # 5) FINAL
        if final_rule and final_rule not in written:
            f.write(final_rule + '\n')
            written.add(final_rule)

        f.write(FOOTER)

    print(f"\nGenerated {output_file} successfully!")

if __name__ == '__main__':
    generate_rules()
