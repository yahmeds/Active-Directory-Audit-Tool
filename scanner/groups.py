from ldap3 import BASE
from ldap3.utils.conv import escape_filter_chars

from scanner.accounts import DISABLED

DOMAIN_ADMINS_RID = 512


def check_domain_admins(conn, base_dn):
    """Return accounts in Domain Admins, nested groups included."""
    findings = []

    # 1. read domain SID from the root of the directory
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=domain)",
        search_scope=BASE,
        attributes=["objectSid"],
    )
    domain_sid = conn.entries[0].objectSid.value

    # 2. find the group whose SID = domain SID + "-512"
    conn.search(
        search_base=base_dn,
        search_filter=f"(objectSid={domain_sid}-{DOMAIN_ADMINS_RID})",
        attributes=["distinguishedName"],
    )
    group_dn = conn.entries[0].distinguishedName.value

    conn.search(
        search_base=base_dn,
        search_filter=(
            "(&(objectCategory=person)(objectClass=user)"
            f"(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(group_dn)}))"
        ),
        attributes=["sAMAccountName", "userAccountControl"],
    )

    for entry in conn.entries:
        name = str(entry.sAMAccountName)
        uac = int(entry.userAccountControl.value)


        if not uac & DISABLED:
            findings.append(name)
    
    return findings

