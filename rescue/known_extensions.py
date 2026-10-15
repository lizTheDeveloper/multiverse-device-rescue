"""Browser extensions from well-known password managers, by store ID.

Matched by ID, never by name: anything can call itself "LastPass", but a
Chrome Web Store ID is tied to the publisher's signing key. Chrome, Brave and
Edge all install from the Chrome Web Store, so one table covers them. An ID
missing from here only means the extension isn't recognized, so it gets the
ordinary checks.
"""

CHROME_STORE_UPDATE_URL = "https://clients2.google.com/service/update2/crx"

# Chrome Web Store ID -> name shown to the person.
PASSWORD_MANAGER_CHROME_IDS = {
    "hdokiejnpimakedhajhdlcegeplioahd": "LastPass",
    "aeblfdkhhhdcdjpifhhbdiojplfjncoa": "1Password",
    "nngceckbapebfimnlniiiahkandclblb": "Bitwarden",
    "fdjamakpfbbddfjaooikfcpapjohcfmg": "Dashlane",
    "ghmbeldphafepmbegfdlkpapadhbakde": "Proton Pass",
    "oboonakemofpalcgghocfoadofidjkkk": "KeePassXC",
    "fooolghllnmhmmndgjiamiiodkpenpbb": "NordPass",
    "bfogiafebfohielmmehodmfbbebbbpei": "Keeper",
    "pnlccmojcmeohlpggmfnbbiapkmbliob": "RoboForm",
    "kmcfomidfpdkfieipokbalgegidffkal": "Enpass",
}

# Firefox add-on ID -> name.
PASSWORD_MANAGER_FIREFOX_IDS = {
    "support@lastpass.com": "LastPass",
    "{d634138d-c276-4fc8-924b-40a0ea21d284}": "1Password",
    "{446900e4-71c2-419f-a6a7-df9c091e268b}": "Bitwarden",
    "78272b6fa58f4a1abaac99321d503a20@proton.me": "Proton Pass",
}


def password_manager_for(browser: str, ext_id: str, update_url: str | None = None) -> str | None:
    """The password manager this extension is, or None.

    For Chromium browsers the extension must also update from the Chrome Web
    Store, so a side-loaded copy that borrows a store ID doesn't count.
    """
    if browser.lower() == "firefox":
        return PASSWORD_MANAGER_FIREFOX_IDS.get(ext_id)
    name = PASSWORD_MANAGER_CHROME_IDS.get(ext_id)
    if name and update_url == CHROME_STORE_UPDATE_URL:
        return name
    return None
