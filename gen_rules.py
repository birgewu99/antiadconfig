#!/usr/bin/env python3
import yaml
import requests
from datetime import datetime
import os

# Header content for SR config
HEADER = """# Shadowrocket: {datetime}
[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4
dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query, https://dns.google/dns-query, https://cloudflare-dns.com/dns-query,223.5.5.5,119.29.29.29, 8.8.8.8, 1.1.1.1
fallback-dns-server = system
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

def fetch_rules(url):
    """Fetch rules from remote URL"""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        lines = response.text.strip().split('\n')
        return [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []

def parse_rule(rule_lines):
    """RULE-SET 强制输出 REJECT-200"""
    lines = []
    for rule in rule_lines:
        rule = rule.strip().strip("- '\"")
        if not rule or rule.startswith('#') or rule == 'payload:':
            continue

        if rule.startswith('+.'):
            domain = rule[2:]
        elif rule.startswith('.'):
            domain = rule[1:]
        else:
            domain = rule

        lines.append(f"DOMAIN-SUFFIX,{domain},REJECT-200")
    return lines

def generate_rules():
    final_rule = None  # 用来存 FINAL
    proxy_rules = []   # 用来存非 FINAL 的 PROXY
    direct_rules = []  # 用来存 GEOIP DIRECT
    reject_rules = []  # RULE-SET 的 REJECT-200

    # Load sources
    with open('sources.yaml', 'r') as f:
        config = yaml.safe_load(f)

    # 解析规则
    for source in config.get('rules', []):
        stype = source.get('type', '').upper()

        if stype == 'RULE-SET':
            url = source.get('url')
            print(f"Fetching {url}...")
            rule_lines = fetch_rules(url)
            parsed = parse_rule(rule_lines)
            reject_rules.extend(parsed)
            print(f"  Added {len(parsed)} REJECT-200 rules from {url}")

        elif stype == 'GEOIP':
            country = source.get('country', '')
            rule = f"GEOIP,{country},DIRECT"
            direct_rules.append(rule)
            print(f"Added GEOIP DIRECT: {rule}")

        elif stype == 'FINAL':
            final_rule = "FINAL,PROXY"
            print(f"Added FINAL rule: {final_rule}")

        else:
            # 非 RULE-SET、GEOIP、FINAL 的 PROXY 规则
            policy = source.get('policy', '').strip().upper()
            if policy == "PROXY":
                proxy_rules.append(f"{stype},{policy}")  # 或其他格式
                print(f"Added PROXY rule: {stype},{policy}")

    # 写文件
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "sr_rules.conf")

    with open(output_file, 'w') as f:
        f.write(HEADER.format(datetime=now))
        # 顺序：
        # 1️⃣ RULE-SET REJECT-200
        f.write('\n'.join(reject_rules) + '\n')
        # 2️⃣ 非 FINAL PROXY
        if proxy_rules:
            f.write('\n'.join(proxy_rules) + '\n')
        # 3️⃣ GEOIP DIRECT
        if direct_rules:
            f.write('\n'.join(direct_rules) + '\n')
        # 4️⃣ FINAL PROXY 最后
        if final_rule:
            f.write(final_rule + '\n')
        f.write(FOOTER)

    print(f"\nGenerated {output_file} successfully!")

if __name__ == '__main__':
    generate_rules()
