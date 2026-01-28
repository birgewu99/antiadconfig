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
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32, 239.255.255.250/32
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

def parse_rule(rule_text, policy):
    """Parse rule and convert to SR format"""
    lines = []
    for rule in rule_text:
        if rule:
            lines.append(f"{rule},{policy}")
    return lines

def generate_rules():
    """Generate SR rules config"""
    # Load sources
    with open('sources.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    rules = []
    
    # Get current datetime
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Process each rule source
    for source in config['rules']:
        if source['type'] == 'RULE-SET':
            print(f"Fetching {source['url']}...")
            rule_lines = fetch_rules(source['url'])
            parsed = parse_rule(rule_lines, source['policy'])
            rules.extend(parsed)
            print(f"  Added {len(parsed)} rules from {source['url']}")
        
        elif source['type'] == 'GEOIP':
            rule = f"GEOIP,{source['country']},{source['policy']}"
            rules.append(rule)
            print(f"Added: {rule}")
        
        elif source['type'] == 'FINAL':
            rule = f"FINAL,{source['policy']}"
            rules.append(rule)
            print(f"Added: {rule}")
    
    # Generate output
    output_dir = 'output'
    os.makedirs(output_dir, exist_ok=True)
    
    output_file = os.path.join(output_dir, 'sr_rules.conf')
    
    with open(output_file, 'w') as f:
        f.write(HEADER.format(datetime=now))
        f.write('\n'.join(rules))
        f.write(FOOTER)
    
    print(f"\nGenerated {output_file} with {len(rules)} rules")

if __name__ == '__main__':
    generate_rules()
