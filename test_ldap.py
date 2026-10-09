import argparse
import os
from getpass import getpass

from ldap3 import ALL, Connection, Server

parser = argparse.ArgumentParser(description="Test an LDAP connection to an Active Directory domain controller")
parser.add_argument("--server", required=True, help="DC IP or hostname")
parser.add_argument("--port", type=int, default=389, help="LDAP port")
parser.add_argument("--user", required=True, help="Bind account")
args = parser.parse_args()

password = os.environ.get("AD_PASSWORD") or getpass("Password: ")

server = Server(args.server, port=args.port, get_info=ALL)
conn = Connection(server, user=args.user, password=password, auto_bind=True)

print("Bound as:", conn.extend.standard.who_am_i())
print("Detected base DN:", server.info.other["defaultNamingContext"][0])