import argparse
import os
from getpass import getpass

from ldap3 import ALL, Connection, Server

NEVER_EXPIRES = 65536
DISABLED = 2


def check_password_never_expires(conn, base_dn):
    """Return enabled accounts whose password never expires."""
    findings = []

    conn.search(
        search_base=base_dn,
        search_filter="(&(objectCategory=person)(objectClass=user))",
        attributes=["sAMAccountName", "userAccountControl"],
    )

    for entry in conn.entries:
        name = str(entry.sAMAccountName)
        uac = int(entry.userAccountControl.value)

        if uac & NEVER_EXPIRES and not uac & DISABLED:
            findings.append(name)

    return findings



parser = argparse.ArgumentParser(description="Active Directory audit scanner")
parser.add_argument("--server", required=True, help="Domain controller IP or hostname")
parser.add_argument("--port", type=int, default=389, help="LDAP port (default: 389)")
parser.add_argument("--user", required=True, help="Bind account, e.g. user@domain.local")
args = parser.parse_args()

password = os.environ.get("AD_PASSWORD") or getpass("Password: ")

server = Server(args.server, port=args.port, get_info=ALL)
conn = Connection(server, user=args.user, password=password, auto_bind=True)

base_dn = server.info.other["defaultNamingContext"][0]

for account in check_password_never_expires(conn, base_dn):
    print("Password never expires:", account)