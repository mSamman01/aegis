"""Posture advice: version bounds, registry commands, the checker, the ranking and the sanitizer (D47).

Built on data/samples/posture_sample.json, a synthetic export written by hand, plus small edge cases.
Nothing here needs Wazuh, a model or the network.
"""

import contextlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path

from aegis import posture as P
from aegis.cli import main

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "samples" / "posture_sample.json"


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in args])
    return code, out.getvalue(), err.getvalue()


def check_item(rules, condition="all", title="Ensure 'Something' is set to 'Enabled'.", remediation="Do it."):
    return {"id": 1, "title": title, "condition": condition, "remediation": remediation,
            "rules": [{"rule": r} for r in rules], "compliance": [{"key": "cis", "value": "18.1"}]}


class BoundTests(unittest.TestCase):
    def test_versions_compare_as_numbers(self):
        self.assertGreater(P.version_key("3.13.14"), P.version_key("3.13.9"))
        self.assertEqual(P.version_key("26.2"), P.version_key("26.2.0"))
        self.assertLess(P.version_key("3.12.10150.0"), P.version_key("3.13"))

    def test_the_version_that_fixes_every_cve(self):
        # the real laptop's Python, by shape: SENTINEL's model once stated such a rule backwards
        bound = P.fixing_bound([("a", "Package less than 3.13.14"), ("b", "Package less than 3.12.13"),
                                ("c", "Package less than or equal to 3.14.4"), ("d", "Package less than 3.13.10")])
        self.assertEqual((bound.version, bound.newer_than), ("3.14.4", True))
        self.assertEqual(bound.text(), "a version newer than 3.14.4")
        bound = P.fixing_bound([("a", "Package less than 26.2"), ("b", "Package less than 26.1.2")])
        self.assertEqual(bound.text(), "version 26.2 or newer")

    def test_a_range_and_an_unreadable_bound(self):
        bound = P.fixing_bound([("a", "Package greater than or equal to 2.0 and less than 2.4.1"),
                                ("b", "Package affected, see the vendor")])
        self.assertEqual((bound.version, bound.unread), ("2.4.1", ("b",)))
        self.assertIsNone(P.fixing_bound([("b", "")]).version)

    def test_every_bound_in_the_sample_fixes_every_cve(self):
        posture = P.load(SAMPLE)
        self.assertEqual({p.name: p.bound.text() for p in posture.programs},
                         {"Example Browser": "version 119.0 or newer", "pip": "version 24.0 or newer"})
        for program in posture.programs:
            self.assertTrue(all(P.fixes(program.bound, cve.condition) for cve in program.cves), program.name)
        self.assertFalse(P.fixes(P.Bound("3.14.4"), "Package less than or equal to 3.14.4"))
        self.assertEqual(posture.solved, 1)  # the archiver's CVE was solved after it was raised


class RegistryTests(unittest.TestCase):
    KEY = r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"

    def steps(self, rules, **options):
        return P.registry_steps(P.read_check("cis", check_item(rules, **options)))

    def test_a_policy_value_gets_one_checked_command(self):
        steps, why = self.steps([f"r:{self.KEY}", f"r:{self.KEY} -> EnableSmartScreen",
                                 f"r:{self.KEY} -> EnableSmartScreen -> 1"])
        self.assertEqual(why, "")
        self.assertEqual([s.text for s in steps], [
            r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 1 /f',
            r'reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen"'])

    def test_compare_and_choice_take_a_value_that_passes(self):
        lsa = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        for content, data in (("n:^(\\d+) compare <= 4", "4"), ("n:^(\\d+) compare > 3", "4"),
                              ("r:^1$|^2$|^3$", "1")):
            check = P.read_check("cis", check_item([f"r:{lsa} -> X -> {content}"]))
            self.assertEqual(P.chosen_data(check.targets[0]), data)
            self.assertTrue(check.targets[0].satisfied_by(data))
            self.assertIn(f"/d {data} /f", P.registry_steps(check)[0][0].text)

    def test_types_only_where_they_are_known(self):
        winlogon = r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        steps, why = self.steps([f"r:{winlogon} -> CachedLogonsCount -> n:^(\\d+) compare <= 4"])
        self.assertEqual(steps, [])
        self.assertIn("registry type of CachedLogonsCount is not known", why)
        rules = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
        steps, _ = self.steps([f"r:{rules} -> 56a863a9-875e-4185-98a7-b882c64b5ce5 -> 1"])
        self.assertIn("/t REG_SZ /d \"1\"", steps[0].text)  # ASR rule states are numbers stored as text
        service = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM"
        self.assertIn("/t REG_DWORD /d 4", self.steps([f"r:{service} -> Start -> 4"])[0][0].text)

    def test_names_that_are_not_safe_in_a_command_get_none(self):
        for rule in (f'r:{self.KEY} -> Evil" & del C:\\ -> 1', f"r:{self.KEY}\\a&b -> X -> 1",
                     r"r:HKEY_CLASSES_ROOT\x -> X -> 1", f"r:{self.KEY} -> X -> 1 | calc"):
            steps, why = self.steps([rule])
            self.assertEqual(steps, [], rule)
            self.assertTrue(why, rule)

    def test_rules_that_are_not_a_plain_setting_get_none(self):
        cases = {
            "any": ([f"r:{self.KEY} -> X -> 1"], {"condition": "any"}),
            "command": (["c:net accounts -> n:Minimum password length:\\s+(\\d+) compare >= 14"], {}),
            "pattern": ([f"r:{self.KEY} -> X -> r:^\\d+ ?"], {}),
            "negation": ([f"not r:{self.KEY} -> X"], {}),
        }
        for name, (rules, options) in cases.items():
            self.assertEqual(self.steps(rules, **options)[0], [], name)


class CheckerTests(unittest.TestCase):
    def test_settings_that_weaken_the_pc_are_dropped(self):
        for path, value, data in (
                (r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", "1"),
                (r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", "1"),
                (r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile", "EnableFirewall", "0"),
                (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", "0"),
                (r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", "1"),
                (r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", "1"),
                (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", "1")):
            step = P.Step("run", f'reg add "{path}" /v "{value}" /t REG_DWORD /d {data} /f', "Aegis")
            self.assertIsNotNone(P.check_step(step), value)
        safe = P.Step("run", r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v '
                             r'"DisableAntiSpyware" /t REG_DWORD /d 0 /f', "Aegis")
        self.assertIsNone(P.check_step(safe))  # turning Defender's off-switch off is hardening

    def test_commands_in_wazuhs_text_that_weaken_the_pc_are_dropped(self):
        for text in ("Run Set-MpPreference -DisableRealtimeMonitoring $true first.",
                     "Add-MpPreference -ExclusionPath C:\\temp", "netsh advfirewall set allprofiles state off",
                     "Set-ExecutionPolicy Bypass -Scope Process", "powershell -ExecutionPolicy Unrestricted -File x.ps1",
                     "sc config WinDefend start= disabled", "bcdedit /set nointegritychecks on",
                     "wevtutil cl Security", "reg add HKLM\\Software\\X /v Y /d 1 /f"):
            self.assertIsNotNone(P.check_step(P.Step("do", text, "CIS, via Wazuh")), text)

    def test_cis_wording_is_not_mistaken_for_a_command(self):
        for text in ("To establish the recommended configuration via GP, set the following UI path to Disabled: "
                     "Computer Configuration\\...\\Microsoft Defender Antivirus\\Turn off Microsoft Defender Antivirus",
                     "Set 'Windows Firewall: Public: Firewall state' to On (recommended).",
                     "Turn off the firewall notification for the domain profile."):
            self.assertIsNone(P.check_step(P.Step("do", text, "CIS, via Wazuh")), text)

    def test_links_only_to_known_sites(self):
        self.assertTrue(P.allowed_link("https://learn.microsoft.com/en-us/windows/security/x"))
        self.assertTrue(P.allowed_link("https://cti.wazuh.com/vulnerabilities/cves/CVE-2026-1"))
        for url in ("http://learn.microsoft.com/x", "https://microsoft.com.evil.example/x",
                    "https://evil.example/?u=microsoft.com", "javascript:alert(1)", "https://x.org/a b"):
            self.assertFalse(P.allowed_link(url), url)


class AdviceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.posture = P.load(SAMPLE)
        cls.advice = P.rank(cls.posture)
        cls.by_id = {a.item: a for a in cls.advice}

    def test_every_command_passes_its_checks_rule_and_the_checker(self):
        checks = {f"check {c.id}": c for c in self.posture.checks}
        commands = 0
        for item in self.advice:
            for step in item.steps:
                self.assertIsNone(P.check_step(step), step.text)
                match = re.match(r'^reg add "[^"]+" /v "([^"]+)" /t \w+ /d "?([^" ]+)"? /f$', step.text)
                if match:
                    commands += 1
                    target = next(t for t in checks[item.item].targets if t.value == match.group(1))
                    self.assertTrue(target.satisfied_by(match.group(2)), step.text)
        self.assertEqual(commands, 10)  # SmartScreen and the ASR rules set two values each

    def test_the_planted_text_is_removed_and_the_real_setting_kept(self):
        item = self.by_id["check 90013"]
        self.assertEqual([why for _, why in item.removed], ["turns parts of Microsoft Defender off"])
        self.assertTrue(any("/v \"DisableRealtimeMonitoring\" /t REG_DWORD /d 0" in s.text for s in item.steps))

    def test_commands_that_can_lock_you_out_or_break_things_are_held_back(self):
        for item, why in (("check 90003", "lock you out"), ("check 90004", "firewall rules your programs created"),
                          ("check 90009", "printing off")):
            advice = self.by_id[item]
            self.assertFalse(any(s.kind == "run" for s in advice.steps), item)
            self.assertIn(why, advice.held[0][1])
            self.assertTrue(any(s.source == "CIS, via Wazuh" for s in advice.steps))  # the advice itself stays

    def test_warnings_and_home_notes(self):
        self.assertTrue(self.by_id["check 90002"].notes[0].startswith("Very old network storage"))
        bitlocker = self.by_id["check 90005"]
        self.assertIn("Windows 11 Home has no BitLocker management", bitlocker.notes[0])
        self.assertLess(bitlocker.score, 10)

    def test_the_ranking(self):
        order = [a.item for a in self.advice]
        self.assertEqual(order[0], "program: Example Browser 118.0.2")  # 9.8, reachable without signing in
        self.assertLess(order.index("check 90001"), order.index("check 90011"))  # guest logons over firewall logs
        self.assertLess(order.index("check 90011"), len(order))
        browser = self.by_id["program: Example Browser 118.0.2"]
        self.assertEqual(browser.score, 49 + 15 + 5 + 3)
        self.assertNotIn("check 90014", self.by_id)  # passed
        self.assertNotIn("check 90015", self.by_id)  # not applicable

    def test_nothing_here_asks_a_model(self):
        source = Path(P.__file__).read_text(encoding="utf-8")
        self.assertNotIn("aegis.llm", source)
        self.assertNotIn("investigate", source)


class SharingTests(unittest.TestCase):
    def test_names_addresses_sids_and_profiles_are_replaced(self):
        text = (r"LenovoX at 192.168.56.1 as S-1-5-21-1111-2222-3333-1001 in C:\Users\misse\AppData and "
                r"c:\users\Misse\x")
        shared = P.sanitize(text, ["lenovox", "misse"])
        self.assertEqual(shared, r"<name> at <address> as <sid> in C:\Users\<user>\AppData and c:\users\<user>\x")
        P.check_shareable(shared, ["lenovox", "misse"])

    def test_a_copy_that_still_holds_a_name_is_refused(self):
        with self.assertRaises(P.SanitizeError):
            P.check_shareable("written on LenovoX", ["LenovoX"])

    def test_the_command_writes_the_report_and_a_clean_shareable_copy(self):
        with tempfile.TemporaryDirectory() as folder:
            code, out, err = run_cli("posture", "--from", SAMPLE, "--out", folder, "--shareable", "--hide", "labuser")
            self.assertEqual(code, 0, err)
            self.assertIn("Checker   1 steps removed", out)
            self.assertIn(" 1.  72  Example Browser", out)
            for name in ("report.md", "index.html", "advice.json", "shareable.md", "shareable.html", "style.css"):
                self.assertTrue((Path(folder) / name).is_file(), name)
            shared = (Path(folder) / "shareable.md").read_text(encoding="utf-8")
            self.assertNotIn("win-laptop", shared)
            self.assertIn("win-laptop", (Path(folder) / "report.md").read_text(encoding="utf-8"))
            page = (Path(folder) / "index.html").read_text(encoding="utf-8")
            self.assertIn("Content-Security-Policy", page)
            self.assertNotIn("<script", page)
            record = json.loads((Path(folder) / "advice.json").read_text(encoding="utf-8"))
            self.assertEqual(record["failed"], 13)

    def test_command_errors(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(run_cli("posture", "--from", SAMPLE, "--out", folder, "--hide", "x")[0], 2)
            self.assertEqual(run_cli("posture", "--from", Path(folder) / "missing.json", "--out", folder)[0], 2)
            bad = Path(folder) / "bad.json"
            bad.write_text('{"something": "else"}', encoding="utf-8")
            code, _, err = run_cli("posture", "--from", bad, "--out", folder)
            self.assertEqual(code, 2)
            self.assertIn("not a file written by lab/aegis-posture", err)


if __name__ == "__main__":
    unittest.main()
