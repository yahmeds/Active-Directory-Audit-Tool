from scanner.accounts import DISABLED
from scanner.models import Finding

TRUSTED_FOR_DELEGATION = 524288
DOMAIN_CONTROLLERS_GROUP_ID = 516


def check_unconstrained_delegation(conn, base_dn):
    """Return enabled non-DC accounts trusted for unconstrained delegation."""
    accounts = []

    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=user)",
        attributes=["sAMAccountName", "userAccountControl", "primaryGroupID"],
    )

    for entry in conn.entries:
        name = str(entry.sAMAccountName)
        uac = int(entry.userAccountControl.value)
        group_id = int(entry.primaryGroupID.value)

        if uac & TRUSTED_FOR_DELEGATION and not uac & DISABLED and group_id != DOMAIN_CONTROLLERS_GROUP_ID:
             accounts.append(name)

    if not accounts:
        return None
    
    return Finding(
        id="UNCONSTRAINED-DELEGATION",
        title="Unconstrained Kerberos delegation",
        severity="high",
        description="These accounts are trusted to store a copy of the identity of every user who connects to them. If one is compromised, an attacker can impersonate those users, including administrators.",
        remediation="Remove unconstrained delegation, or switch to constrained delegation or RBCD. Add administrator accounts to the Protected Users group, or flag them as 'sensitive and cannot be delegated'.",
        accounts=accounts,
    )