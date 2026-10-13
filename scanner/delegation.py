from scanner.accounts import DISABLED

TRUSTED_FOR_DELEGATION = 524288
DOMAIN_CONTROLLERS_GROUP_ID = 516


def check_unconstrained_delegation(conn, base_dn):
    """Return enabled non-DC accounts trusted for unconstrained delegation."""
    findings = []

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
             findings.append(name)

    return findings