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
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 2[...]
dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query, https://dns.google/dns-query, https://cloudflare-dns.com/dns-query,223.5.5.5,119.29.29.29, 8.8.8.8, 1.1.1.1
fallback-dns-server = system

# Enable full IPv6 support
ipv6 = false
prefer-ipv6 = false

# If a domain uses the direct policy, after enabling this, Shadowrocket will use the system DNS to resolve it.
dns-direct-system = true

# If true, Shadowrocket will automatically reply to ICMP packets.
icmp-auto-reply = true

# If true, Shadowrocket always executes reject urlrewrite rules even though the global routing is not config.
always-reject-url-rewrite = true

# If false, the domain resolution returns a private IP and Shadowrocket assumes that the domain is hijacked and forces the use of a proxy.
private-ip-answer = true

# If a domain uses the direct policy, automatically switch to the proxy rule if direct DNS resolution fails.
dns-direct-fallback-proxy = false

# The fallback behavior when UDP traffic matches a policy that doesn't support the UDP relay. Possible values: DIRECT, REJECT.
udp-policy-not-supported-behaviour = REJECT

# By default, DNS lookup is always performed on the remote server with a proxy policy.
# If true, Shadowrocket will use the mapped address for the proxy connection instead of the host if a local DNS mapping exists.
use-local-host-item-for-proxy = false

[Rule]
"""

# Footer content for SR config
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
        # Filter out comments and empty lines
        return [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []

def parse_rule(rule_lines, policy):
    """Parse raw rules and convert to Shadowrocket format"""
    lines = []
    policy_name = f"{policy}-DROP"  # 例如 REJECT -> REJECT-DROP
    for rule in rule_lines:
        rule = rule.strip().strip("- '\"")  # 去掉 - ' 和引号
        if not rule or rule.startswith('#') or rule == 'payload:':
            continue

        # Clash 风格 +.xxx 转 DOMAIN-SUFFIX
        if rule.startswith('+.'):
            domain = rule[2:]
            lines.append(f"DOMAIN-SUFFIX,{domain},{policy_name}")
        # 单纯的 .xxx 或其他规则也当 DOMAIN-SUFFIX
        elif rule.startswith('.'):
            domain = rule[1:]
            lines.append(f"DOMAIN-SUFFIX,{domain},{policy_name}")
        else:
            # 其他规则直接加上 policy
            lines.append(f"DOMAIN-SUFFIX,{rule},{policy_name}")
    return lines

def generate_rules():
    """Generate SR rules config with ordering: REJECT -> DIRECT -> PROXY -> others"""
    # Load sources
    with open('sources.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # policy -> list of rules (preserve insertion order within each policy)
    policy_buckets = {}
    # record order of first-seen policies to preserve relative order for "other" policies
    seen_policies = []

    # Get current datetime
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Helper to add a rule to a policy bucket
    def add_to_bucket(policy, rule_or_rules):
        p = policy.strip().upper()
        if p not in policy_buckets:
            policy_buckets[p] = []
            seen_policies.append(p)
        if isinstance(rule_or_rules, list):
            policy_buckets[p].extend(rule_or_rules)
        else:
            policy_buckets[p].append(rule_or_rules)

    # Process each rule source
    for source in config.get('rules', []):
        stype = source.get('type', '').upper()
        if stype == 'RULE-SET':
            url = source.get('url')
            policy = source.get('policy', '').strip().upper()
            print(f"Fetching {url}...")
            rule_lines = fetch_rules(url)
            parsed = parse_rule(rule_lines, policy)
            add_to_bucket(policy, parsed)
            print(f"  Added {len(parsed)} rules from {url}")
        
        elif stype == 'GEOIP':
            policy = source.get('policy', '').strip().upper()
            country = source.get('country', '')
            rule = f"GEOIP,{country},{policy}"
            add_to_bucket(policy, rule)
            print(f"Added: {rule}")
        
        elif stype == 'FINAL':
            policy = source.get('policy', '').strip().upper()
            rule = f"FINAL,{policy}"
            add_to_bucket(policy, rule)
            print(f"Added: {rule}")
    
    # Merge buckets in desired global order
    final_rules = []
    # Desired priority order
    priority = ['REJECT', 'DIRECT', 'PROXY']
    added_policies = set()

    # Add priority policies first if present
    for p in priority:
        if p in policy_buckets:
            final_rules.extend(policy_buckets[p])
            added_policies.add(p)
    
    # Add any remaining policies in the order they were first seen
    for p in seen_policies:
        if p not in added_policies:
            final_rules.extend(policy_buckets.get(p, []))
            added_policies.add(p)
    
    total_rules = sum(len(v) for v in policy_buckets.values())

    # Generate output
    output_dir = 'output'
    os.makedirs(output_dir, exist_ok=True)
    
    output_file = os.path.join(output_dir, 'sr_rules.conf')

    seen = set()
    final_rules_unique = []
    for r in final_rules:
        if r not in seen:
            final_rules_unique.append(r)
            seen.add(r)
    
    with open(output_file, 'w') as f:
        f.write(HEADER.format(datetime=now))
        f.write('\n'.join(final_rules))
        f.write(FOOTER)
    
    print(f"\nGenerated {output_file} with {total_rules} rules")

if __name__ == '__main__':
    generate_rules()
