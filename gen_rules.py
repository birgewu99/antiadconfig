#!/usr/bin/env python3
import yaml
import requests
from datetime import datetime
import os

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
    """解析 RULE-SET，is_ip=True 时输出 IP-CIDR"""
    lines = []
    for rule in rule_lines:
        rule = rule.strip().strip("- '\"")
        if not rule or rule.startswith('#') or rule == 'payload:':
            continue

        if is_ip:
            lines.append(f"IP-CIDR,{rule},{policy}")
        else:
            # DOMAIN-SUFFIX
            if rule.startswith('+.'):
                domain = rule[2:]
            elif rule.startswith('.'):
                domain = rule[1:]
            else:
                domain = rule

            # special handling for domains containing "douyin":
            # 1) if domain contains 'douyin' and policy == 'REJECT-200' => keep as is
            # 2) if domain contains 'douyin' and policy == 'DIRECT'    => change to 'PROXY'
            # For safety, match case-insensitive and don't mutate the original policy variable.
            policy_to_use = policy
            if 'douyin' in domain.lower():
                if policy == 'DIRECT':
                    policy_to_use = 'PROXY'
                else:
                    # keep policy as-is (including 'REJECT-200')
                    policy_to_use = policy

            lines.append(f"DOMAIN-SUFFIX,{domain},{policy_to_use}")
    return lines

def generate_rules():
    final_rule = None
    proxy_rules = []
    geoip_rules = []
    ruleset_rules = []

    with open('sources.yaml', 'r') as f:
        config = yaml.safe_load(f)

    for source in config.get('rules', []):
        stype = source.get('type', '').upper()
        url = source.get('url', '')
        policy = source.get('policy', '').upper() or "REJECT-200"

        if stype == 'RULE-SET' and url:
            print(f"Fetching {url} ...")
            rule_lines = fetch_rules(url)
            is_ip = any(k in url.lower() for k in IP_CIDR_KEYWORDS)
            parsed = parse_rule(rule_lines, policy=policy, is_ip=is_ip)
            ruleset_rules.extend(parsed)
            print(f"  Added {len(parsed)} rules from {url} ({'IP-CIDR' if is_ip else 'DOMAIN-SUFFIX'})")

        elif stype == 'GEOIP':
            country = source.get('country', '').upper()
            geoip_rules.append(f"GEOIP,{country},{policy}")
            print(f"Added GEOIP rule: GEOIP,{country},{policy}")

        elif stype == 'FINAL':
            final_rule = f"FINAL,{policy}" if policy else "FINAL,PROXY"
            print(f"Added FINAL rule: {final_rule}")

        else:
            # 其他类型默认处理为 PROXY
            if policy == "PROXY":
                proxy_rules.append(f"{stype},{policy}")
                print(f"Added PROXY rule: {stype},{policy}")

    # 写入文件
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "sr_rules.conf")

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(HEADER.format(datetime=now))
        # 1️⃣ RULE-SET
        f.write('\n'.join(ruleset_rules) + '\n')
        # 2️⃣ PROXY
        if proxy_rules:
            f.write('\n'.join(proxy_rules) + '\n')
        # 3️⃣ GEOIP
        if geoip_rules:
            f.write('\n'.join(geoip_rules) + '\n')
        # 4️⃣ FINAL
        if final_rule:
            f.write(final_rule + '\n')
        f.write(FOOTER)

    print(f"\nGenerated {output_file} successfully!")

if __name__ == '__main__':
    generate_rules()
