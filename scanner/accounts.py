from scanner.models import Finding

NEVER_EXPIRES = 65536
DISABLED = 2
DONT_REQ_PREAUTH = 4194304


def check_password_never_expires(conn, base_dn):
    """Return enabled accounts whose password never expires."""
    accounts  = []

    conn.search(
        search_base=base_dn,
        search_filter="(&(objectCategory=person)(objectClass=user))",
        attributes=["sAMAccountName", "userAccountControl"],
    )

    for entry in conn.entries:
        name = str(entry.sAMAccountName)
        uac = int(entry.userAccountControl.value)

        if uac & NEVER_EXPIRES and not uac & DISABLED:
            accounts.append(name)
    if not accounts:
        return None
    
    return Finding(
        id="PWD-NEVER-EXPIRES",
        title="Passwords that never expire",
        severity="medium",
        description="A password that is never changed stays valid forever, so a leaked or guessed one gives lasting access.",
        remediation="Remove the 'password never expires' flag and enforce a maximum password age. For service accounts, use gMSA.",
        accounts=accounts,
    )

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

def check_asrep_roastable(conn, base_dn):
    findings = []
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectCategory=person)(objectClass=user))",
        attributes=["sAMAccountName", "userAccountControl"],
    )

    for entry in conn.entries:
        name = str(entry.sAMAccountName)
        uac = int(entry.userAccountControl.value)

        if uac & DONT_REQ_PREAUTH and not uac & DISABLED : 
            findings.append(name)
    
    return findings