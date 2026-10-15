import argparse
import os
from getpass import getpass

from ldap3 import ALL, Connection, Server

from scanner.accounts import check_password_never_expires, check_kerberoastable, check_asrep_roastable
from scanner.groups import check_domain_admins
from scanner.delegation import check_unconstrained_delegation

parser = argparse.ArgumentParser(description="Active Directory audit scanner")
parser.add_argument("--server", required=True, help="Domain controller IP or hostname")
parser.add_argument("--port", type=int, default=389, help="LDAP port (default: 389)")
parser.add_argument("--user", required=True, help="Bind account, e.g. user@domain.local")
args = parser.parse_args()

password = os.environ.get("AD_PASSWORD") or getpass("Password: ")

server = Server(args.server, port=args.port, get_info=ALL)
conn = Connection(server, user=args.user, password=password, auto_bind=True)
base_dn = server.info.other["defaultNamingContext"][0]

checks = [
    check_password_never_expires,
    check_kerberoastable,
    check_asrep_roastable,
    check_domain_admins,
    check_unconstrained_delegation,
]

results = []
for check in checks:
    finding = check(conn, base_dn)
    if finding:
        results.append(finding)

for f in results:
    print(f"[{f.severity.upper()}] {f.title}")
    print("  Accounts:", ", ".join(f.accounts))
    print("  Why:", f.description)
    print("  Fix:", f.remediation)





