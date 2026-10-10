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

def check_kerberoastable(conn, base_dn): 
    findings = []

    conn.search(
        search_base=base_dn,
        search_filter="(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
        attributes=["sAMAccountName", "userAccountControl"],
    )
    for entry in conn.entries:
        name = str(entry.sAMAccountName)
        uac = int(entry.userAccountControl.value)

        if not uac & DISABLED :
            findings.append(name)

    return findings
