import contextlib
import io
import os
import plistlib
import runpy
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ElementTree
from unittest import mock

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)



@contextlib.contextmanager
def chdir(path):
    cwd = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(cwd)


# alfred.py reads info.plist from the working directory when it's imported
with chdir(SRC):
    import alfred  # noqa: E402
    import otp  # noqa: E402
    import workflow  # noqa: E402, F401

CONFIG_NAME = "google-authenticator"
LEGACY_CONFIG = ".gauth"
KEYWORD = "ga"

# RFC 6238 test secret ("12345678901234567890" in base32) and its SHA-1 codes
SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
VECTORS = {59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"}

CMD = 1048576
ALT = 524288


class OtpTest(unittest.TestCase):
    def token_at(self, timestamp, **key):
        with mock.patch("otp.time.time", return_value=timestamp):
            return otp.get_totp_token(otp.get_hotp_key(**key))

    def test_rfc_6238_vectors(self):
        for timestamp, code in VECTORS.items():
            self.assertEqual(self.token_at(timestamp, secret=SECRET), code)

    def test_secrets_ignore_spaces_and_case(self):
        spaced = " ".join(SECRET[i:i + 4] for i in range(0, len(SECRET), 4)).lower()
        self.assertEqual(self.token_at(59, secret=spaced), "287082")

    def test_unpadded_secrets(self):
        self.assertEqual(self.token_at(59, secret="JBSWY3DPEHPK3PX"), self.token_at(59, secret="JBSWY3DPEHPK3PX="))

    def test_hexkey(self):
        self.assertEqual(self.token_at(59, hexkey=b"12345678901234567890".hex()), "287082")

    def test_secret_validation(self):
        self.assertTrue(otp.is_otp_secret_valid(SECRET))
        self.assertTrue(otp.is_otp_secret_valid("jbsw y3dp ehpk 3pxp"))
        self.assertFalse(otp.is_otp_secret_valid(""))
        self.assertFalse(otp.is_otp_secret_valid("not base32!"))


class ItemTest(unittest.TestCase):
    def test_leaves_out_empty_fields(self):
        item = alfred.Item({"uid": 1}, "Title", None).xml()
        self.assertEqual(item.get("uid"), "1")
        self.assertEqual([e.tag for e in item], ["title"])


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.env = {"HOME": self.home.name, "XDG_CONFIG_HOME": ""}

    def path(self, *parts):
        return os.path.join(self.home.name, *parts)

    def write_config(self, *parts, accounts=("Google",)):
        os.makedirs(os.path.dirname(self.path(*parts)), exist_ok=True)
        with open(self.path(*parts), "w") as f:
            for account in accounts:
                f.write("[{}]\nsecret={}\n\n".format(account, SECRET))

    def run_workflow(self, action, query=""):
        # Alfred runs `python3 workflow.py <action> "{query}"` from the workflow's folder
        output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        with mock.patch.dict(os.environ, self.env), mock.patch.object(sys, "argv", ["workflow.py", action, query]), \
                contextlib.redirect_stdout(output), chdir(SRC):
            runpy.run_path("workflow.py", run_name="__main__")
        output.flush()
        return output.buffer.getvalue().decode("utf-8")

    def search(self, query=""):
        root = ElementTree.fromstring(self.run_workflow("search_by_account", query))
        return [
            {"title": item.findtext("title"), "subtitle": item.findtext("subtitle"), "arg": item.get("arg"), "icon": item.findtext("icon")}
            for item in root
        ]

    def test_lists_accounts_with_codes(self):
        self.write_config(".config", CONFIG_NAME, accounts=("Google", "GitHub"))
        items = self.search()
        self.assertEqual([i["title"] for i in items], ["Google", "GitHub"])
        for item in items:
            self.assertRegex(item["arg"], r"^\d{6}$")
            self.assertEqual(item["subtitle"], item["arg"])

    def test_shows_at_most_twenty_accounts(self):
        self.write_config(".config", CONFIG_NAME, accounts=["Account {}".format(i) for i in range(25)])
        self.assertEqual(len(self.search()), 20)

    def test_key_and_hexkey_accounts(self):
        os.makedirs(self.path(".config"))
        with open(self.path(".config", CONFIG_NAME), "w") as f:
            f.write("[Key]\nkey=12345678901234567890\n\n[Hex]\nhexkey={}\n".format(b"12345678901234567890".hex()))
        with mock.patch("otp.time.time", return_value=59):
            items = self.search()
        self.assertEqual([(i["title"], i["arg"]) for i in items], [("Key", "287082"), ("Hex", "287082")])

    def test_invalid_secret_does_not_hide_other_accounts(self):
        os.makedirs(self.path(".config"))
        with open(self.path(".config", CONFIG_NAME), "w") as f:
            f.write("[Broken]\nsecret=not base32!\n\n[Google]\nsecret={}\n".format(SECRET))
        broken, google = self.search()
        self.assertEqual((broken["title"], broken["subtitle"], broken["icon"]), ("Broken", "Invalid secret", "error.png"))
        self.assertEqual(google["title"], "Google")

    def test_commands_are_not_searched(self):
        self.write_config(".config", CONFIG_NAME, accounts=("add",))
        self.assertEqual(self.search("add"), [])

    def test_unescapes_alfred_queries(self):
        self.write_config(".config", CONFIG_NAME, accounts=("My Bank",))
        self.assertEqual([i["title"] for i in self.search("my\\ bank")], ["My Bank"])

    def test_unknown_action(self):
        with self.assertRaises(RuntimeError):
            self.run_workflow("delete_everything")

    def test_filters_accounts_case_insensitively(self):
        self.write_config(".config", CONFIG_NAME, accounts=("Google", "GitHub", "Dropbox"))
        self.assertEqual([i["title"] for i in self.search("git")], ["GitHub"])

    def test_no_match_names_the_config_file(self):
        self.write_config(".config", CONFIG_NAME)
        [item] = self.search("nope")
        self.assertEqual(item["title"], "Account not found")
        self.assertIn("in your config file (~/.config/{})".format(CONFIG_NAME), item["subtitle"])
        self.assertEqual(item["icon"], "warning.png")

    def test_creates_config_when_missing(self):
        [item] = self.search()
        self.assertIn("not yet configured", item["title"])
        self.assertTrue(os.path.isfile(self.path(".config", CONFIG_NAME)))
        self.assertFalse(os.path.exists(self.path(LEGACY_CONFIG)))

    def test_invalid_config_shows_an_error(self):
        os.makedirs(self.path(".config"))
        with open(self.path(".config", CONFIG_NAME), "w") as f:
            f.write("secret=no section header\n")
        [item] = self.search()
        self.assertIn("Invalid syntax", item["title"])
        self.assertEqual(item["icon"], "error.png")
        self.assertIn("Invalid syntax", self.run_workflow("add_account", "Google, " + SECRET))

    def test_falls_back_to_legacy_config(self):
        self.write_config(LEGACY_CONFIG, accounts=("Legacy",))
        self.assertEqual([i["title"] for i in self.search()], ["Legacy"])
        self.assertFalse(os.path.exists(self.path(".config", CONFIG_NAME)))

    def test_prefers_new_config_over_legacy(self):
        self.write_config(LEGACY_CONFIG, accounts=("Legacy",))
        self.write_config(".config", CONFIG_NAME, accounts=("New",))
        self.assertEqual([i["title"] for i in self.search()], ["New"])

    def test_respects_xdg_config_home(self):
        self.env["XDG_CONFIG_HOME"] = self.path("xdg")
        self.write_config("xdg", CONFIG_NAME, accounts=("Xdg",))
        self.assertEqual([i["title"] for i in self.search()], ["Xdg"])

    def test_adds_account(self):
        self.write_config(".config", CONFIG_NAME)
        self.assertIn("A new account was added", self.run_workflow("add_account", "My Bank, " + SECRET))
        self.assertEqual([i["title"] for i in self.search()], ["Google", "My Bank"])

    def test_adds_first_account(self):
        self.assertEqual(self.run_workflow("add_account", "Google, " + SECRET).strip(), "A new account was added:\n[Google]")
        self.assertEqual([i["title"] for i in self.search()], ["Google"])

    def test_add_rejects_duplicates_and_bad_input(self):
        self.write_config(".config", CONFIG_NAME)
        self.assertIn("Account already exists", self.run_workflow("add_account", "Google, " + SECRET))
        self.assertIn("Invalid secret", self.run_workflow("add_account", "Bank, not base32!"))
        self.assertIn("Invalid arguments", self.run_workflow("add_account", "Bank " + SECRET))
        self.assertEqual([i["title"] for i in self.search()], ["Google"])


class InfoPlistTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(SRC, "info.plist"), "rb") as f:
            self.plist = plistlib.load(f)
        self.objects = {o["uid"]: o for o in self.plist["objects"]}

    def outputs(self, modifiers):
        [script_filter] = [o for o in self.objects.values() if o["type"] == "alfred.workflow.input.scriptfilter"]
        [connection] = [c for c in self.plist["connections"][script_filter["uid"]] if c["modifiers"] == modifiers]
        action = connection["destinationuid"]
        return connection, [self.objects[c["destinationuid"]] for c in self.plist["connections"][action]]

    def clipboard(self, modifiers):
        _, outputs = self.outputs(modifiers)
        [clipboard] = [o for o in outputs if o["type"] == "alfred.workflow.output.clipboard"]
        return clipboard["config"]

    def test_keywords(self):
        keywords = {o["config"].get("keyword") for o in self.objects.values()}
        self.assertLessEqual({KEYWORD, KEYWORD + " add"}, keywords)

    def test_enter_copies_without_pasting(self):
        self.assertFalse(self.clipboard(0)["autopaste"])

    def test_cmd_pastes(self):
        connection, _ = self.outputs(CMD)
        self.assertTrue(self.clipboard(CMD)["autopaste"])
        self.assertEqual(connection["modifiersubtext"], "Paste {query}")

    def test_alt_shows_large_type(self):
        _, outputs = self.outputs(ALT)
        self.assertEqual([o["type"] for o in outputs], ["alfred.workflow.output.largetype"])

    def test_icons_exist(self):
        for icon in ("icon.png", "warning.png", "error.png"):
            self.assertTrue(os.path.isfile(os.path.join(SRC, icon)), icon)


if __name__ == "__main__":
    unittest.main()
