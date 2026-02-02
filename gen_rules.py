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

# 强制使用 PROXY 的域名单（来自用户需求）
FORCE_PROXY_ENTRIES = [
    "DOMAIN,lf3-static.bytednsdoc.com",
    "DOMAIN,v5-dy-o-abtest.zjcdn.com",
    "DOMAIN-SUFFIX,amemv.com",
    "DOMAIN-SUFFIX,douyincdn.com",
    "DOMAIN-SUFFIX,douyinpic.com",
    "DOMAIN-SUFFIX,douyinstatic.com",
    "DOMAIN-SUFFIX,douyinvod.com",
    "DOMAIN-SUFFIX,idouyinvod.com",
    "DOMAIN-SUFFIX,ixigua.com",
    "DOMAIN-SUFFIX,ixiguavideo.com",
    "DOMAIN-SUFFIX,pstatp.com",
    "DOMAIN-SUFFIX,snssdk.com",
    "DOMAIN-SUFFIX,toutiao.com",
]

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
            lines.append(f"DOMAIN-SUFFIX,{domain},{policy}")
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

    # 应用强制 PROXY 列表：若已存在则替换 policy，否则追加
    if FORCE_PROXY_ENTRIES:
        # 构建现有 ruleset 的查找表 (key -> index)
        existing = {}
        for i, line in enumerate(ruleset_rules):
            parts = line.split(',', 2)
            if len(parts) >= 2:
                key = f"{parts[0].upper()},{parts[1]}"
                existing[key] = i

        added = 0
        replaced = 0
        for entry in FORCE_PROXY_ENTRIES:
            try:
                typ, val = entry.split(',', 1)
            except ValueError:
                continue
            typ = typ.strip().upper()
            val = val.strip()
            # 保持原始类型（DOMAIN 或 DOMAIN-SUFFIX），并设为 PROXY
            formatted = f"{typ},{val},PROXY"
            key = f"{typ},{val}"
            if key in existing:
                # 替换原有条目为 PROXY
                ruleset_rules[existing[key]] = formatted
                replaced += 1
            else:
                # 追加新条目
                ruleset_rules.append(formatted)
                added += 1
        print(f"Enforced FORCE PROXY rules: added={added}, replaced={replaced}")

    # 写入文件（按策略分组并排序：REJECT-200 -> PROXY -> DIRECT -> 其它 -> GEOIP -> FINAL）
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "sr_rules.conf")

    # 合并来自 RULE-SET 的规则和单独收集的 proxy_rules，然后按 policy 分桶
    all_rules = ruleset_rules + proxy_rules
    buckets = {}
    for r in all_rules:
        if ',' in r:
            left, policy = r.rsplit(',', 1)
            policy = policy.strip().upper()
        else:
            left = r
            policy = ''
        buckets.setdefault(policy, []).append(r)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(HEADER.format(datetime=now))

        # 1) REJECT-200 第一（通常是广告/过滤类）
        if buckets.get('REJECT-200'):
            f.write('\n'.join(buckets['REJECT-200']) + '\n')

        # 2) PROXY 然后
        if buckets.get('PROXY'):
            f.write('\n'.join(buckets['PROXY']) + '\n')

        # 3) DIRECT 接着
        if buckets.get('DIRECT'):
            f.write('\n'.join(buckets['DIRECT']) + '\n')

        # 4) 其它策略（按策略名排序，以保证稳定性）
        other_policies = [p for p in buckets.keys() if p not in ('REJECT-200', 'PROXY', 'DIRECT') and p]
        for p in sorted(other_policies):
            f.write('\n'.join(buckets[p]) + '\n')

        # 5) GEOIP
        if geoip_rules:
            f.write('\n'.join(geoip_rules) + '\n')

        # 6️⃣ FINAL
        if final_rule:
            f.write(final_rule + '\n')
        f.write(FOOTER)

    print(f"\nGenerated {output_file} successfully!")

if __name__ == '__main__':
    generate_rules()
