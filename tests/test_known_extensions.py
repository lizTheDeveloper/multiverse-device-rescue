from rescue.known_extensions import password_manager_for

STORE = "https://clients2.google.com/service/update2/crx"


def test_chromium_needs_the_store_id_and_the_store_update_url():
    assert password_manager_for("Chrome", "hdokiejnpimakedhajhdlcegeplioahd", STORE) == "LastPass"
    assert password_manager_for("Chrome", "hdokiejnpimakedhajhdlcegeplioahd", None) is None
    assert password_manager_for("Chrome", "hdokiejnpimakedhajhdlcegeplioahd", "https://evil.example/u") is None
    assert password_manager_for("Chrome", "x" * 32, STORE) is None


def test_firefox_matches_by_addon_id():
    assert password_manager_for("Firefox", "support@lastpass.com") == "LastPass"
    assert password_manager_for("Firefox", "lastpass@evil.example") is None


def test_safari_is_never_matched():
    assert password_manager_for("Safari", "hdokiejnpimakedhajhdlcegeplioahd") is None
