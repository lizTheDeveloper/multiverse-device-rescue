"""The code-requirement reader: who macOS itself says may use a permission.

A TCC.db row's csreq is the code requirement macOS enforces for that grant.
``signer_for`` credits a team only for the plain Developer ID shape (or
Apple's own anchor), and fails closed on anything else. Synthetic strings only.
"""

import pytest

from rescue.code_requirement import APPLE, signer_for

VSC = "com.microsoft.VSCode"
DEVID = (
    'identifier "com.microsoft.VSCode" and anchor apple generic and '
    "certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and "
    "certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and "
    "certificate leaf[subject.OU] = UBF8T346G9"
)


def test_developer_id_requirement_names_its_team():
    assert signer_for(DEVID, VSC) == "UBF8T346G9"


def test_minimal_and_quoted_and_reordered_forms():
    assert signer_for('identifier "com.microsoft.VSCode" and anchor apple generic and '
                      'certificate leaf[subject.OU] = "UBF8T346G9"', VSC) == "UBF8T346G9"
    assert signer_for("anchor apple generic and certificate leaf[subject.OU] = UBF8T346G9 "
                      "and identifier com.microsoft.VSCode", VSC) == "UBF8T346G9"
    assert signer_for(DEVID + "\n", VSC) == "UBF8T346G9"


def test_apple_anchor_counts_as_apple_only_in_apples_namespace():
    assert signer_for('identifier "com.apple.Terminal" and anchor apple', "com.apple.Terminal") == APPLE
    assert signer_for('identifier "com.evil.Terminal" and anchor apple', "com.evil.Terminal") is None
    # Apple's anchor with a team clause too is not a shape we know: fail closed.
    assert signer_for('identifier "com.apple.Terminal" and anchor apple and '
                      "certificate leaf[subject.OU] = UBF8T346G9", "com.apple.Terminal") is None


@pytest.mark.parametrize("text", [
    # an "or" anywhere: someone else's code could satisfy it
    DEVID + " or anchor trusted",
    'identifier "com.microsoft.VSCode" or anchor apple generic and certificate leaf[subject.OU] = UBF8T346G9',
    # negation
    '! identifier "com.other" and identifier "com.microsoft.VSCode" and anchor apple generic and '
    "certificate leaf[subject.OU] = UBF8T346G9",
    'identifier "com.microsoft.VSCode" and !anchor apple and anchor apple generic and '
    "certificate leaf[subject.OU] = UBF8T346G9",
    # nested parentheses, even ones that look harmless
    '(identifier "com.microsoft.VSCode") and anchor apple generic and certificate leaf[subject.OU] = UBF8T346G9',
    'identifier "com.microsoft.VSCode" and anchor apple generic and '
    "(certificate leaf[subject.OU] = UBF8T346G9 or certificate leaf[subject.OU] = EVILTEAM99)",
    # wrong or missing identifier
    DEVID.replace("com.microsoft.VSCode", "com.microsoft.VSCodeX"),
    DEVID.replace("com.microsoft.VSCode", "com.microsoft.vscode"),
    DEVID.replace('identifier "com.microsoft.VSCode" and ', ""),
    # missing OU, malformed OU, two OUs
    'identifier "com.microsoft.VSCode" and anchor apple generic',
    'identifier "com.microsoft.VSCode" and anchor apple generic and certificate leaf[subject.OU] = ubf8t346g9',
    'identifier "com.microsoft.VSCode" and anchor apple generic and certificate leaf[subject.OU] = UBF8T346G',
    DEVID + " and certificate leaf[subject.OU] = EVILTEAM99",
    # missing anchor, a different anchor
    'identifier "com.microsoft.VSCode" and certificate leaf[subject.OU] = UBF8T346G9',
    'identifier "com.microsoft.VSCode" and anchor trusted and certificate leaf[subject.OU] = UBF8T346G9',
    # two identifiers (one maybe the client's)
    'identifier "com.microsoft.VSCode" and identifier "com.evil" and anchor apple generic and '
    "certificate leaf[subject.OU] = UBF8T346G9",
    # extra trailing clauses we don't know (fail closed, even when only stricter)
    DEVID + " and info [CFBundleVersion] = 1",
    DEVID + " and cdhash H\"0123456789abcdef0123456789abcdef01234567\"",
    DEVID + " and",
    DEVID + " and and anchor apple generic",
    DEVID + " UBF8T346G9",
    # identifiers with quotes / escapes
    'identifier "com.microsoft.VSCode\\" or anchor trusted \\"" and anchor apple generic and '
    "certificate leaf[subject.OU] = UBF8T346G9",
    'identifier "com.microsoft.VS"Code and anchor apple generic and certificate leaf[subject.OU] = UBF8T346G9',
    'identifier "com.microsoft.VSCode and anchor apple generic and certificate leaf[subject.OU] = UBF8T346G9',
    'identifier "com.microsoft.VSCode " and anchor apple generic and certificate leaf[subject.OU] = UBF8T346G9',
    # comments other than csreq's own "/* exists */"
    'identifier "com.microsoft.VSCode" /* or anchor trusted */ and anchor apple generic and '
    "certificate leaf[subject.OU] = UBF8T346G9",
    DEVID + " /* exists",
    # no spaces where the parser expects them
    'identifier "com.microsoft.VSCode" and anchor apple generic and certificate leaf[subject.OU]=UBF8T346G9',
    # multi-line or empty or junk
    DEVID.replace(" and anchor", "\nand anchor"),
    "",
    "   ",
    "invalid requirement specification",
])
def test_hostile_or_unknown_shapes_fail_closed(text):
    assert signer_for(text, VSC) is None


def test_non_strings_and_odd_clients_fail_closed():
    assert signer_for(None, VSC) is None
    assert signer_for(DEVID, None) is None
    assert signer_for(DEVID, "") is None
    assert signer_for(DEVID.replace("com.microsoft.VSCode", "com.micro soft"), "com.micro soft") is None
    assert signer_for(DEVID * 50, VSC) is None  # absurdly long


STORE_OR_DEVID = ("anchor apple generic and (certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or "
                  "certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and "
                  "certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and "
                  "certificate leaf[subject.OU] = MXGJJ98X76)")


def test_developer_id_from_one_team_or_the_mac_app_store_pins_that_team():
    """Some vendors' requirement is "Developer ID from us, or the Mac App Store".
    TCC uses a bundle-id row only for an app with that id, and the App Store signs
    an id only for the team that registered it, so either branch is that team's code."""
    assert signer_for(STORE_OR_DEVID, "com.valvesoftware.steam") == "MXGJJ98X76"
    assert signer_for('identifier "com.valvesoftware.steam" and ' + STORE_OR_DEVID, "com.valvesoftware.steam") == "MXGJJ98X76"
    no_comments = STORE_OR_DEVID.replace(" /* exists */", "")
    assert signer_for(no_comments, "com.valvesoftware.steam") == "MXGJJ98X76"


@pytest.mark.parametrize("bad", [
    STORE_OR_DEVID.replace("6.1.9]", "6.1.12]"),                            # another certificate kind
    STORE_OR_DEVID.replace("and certificate leaf[subject.OU] = MXGJJ98X76", ""),  # no team pinned
    STORE_OR_DEVID.replace(" or ", " and "),
    STORE_OR_DEVID + " or anchor apple generic",                           # an extra way in
    STORE_OR_DEVID.replace("anchor apple generic and ", ""),
    STORE_OR_DEVID.replace("(", "").replace(")", ""),                      # precedence changed
    "anchor apple generic and (anchor apple generic or certificate leaf[subject.OU] = MXGJJ98X76)",
    'identifier "com.example.other" and ' + STORE_OR_DEVID,                # identifier for another app
    "!" + STORE_OR_DEVID,
])
def test_store_or_developer_id_shape_is_exact(bad):
    assert signer_for(bad, "com.valvesoftware.steam") is None


def test_store_or_developer_id_never_stands_for_apple():
    assert signer_for(STORE_OR_DEVID, "com.apple.Terminal") is None
