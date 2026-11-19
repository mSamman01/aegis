"""lab/aegis-gate, exercised as a shell script with stand-in firewall tools (D49).

The gate runs on the lab VM as root. Here it runs in the container with NFT/SS/IPCMD pointed at
fakes (the same seam the gate documents - sudo strips those env vars on the VM), so the firewall
logic and every refusal are checked without root, nftables, or a VM. Account actions (lock/unlock)
need real users and are covered on the VM and by the GateExecutor tests, not here.

Skipped where bash is absent (Windows CI).
"""

import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

GATE = Path(__file__).resolve().parent.parent / "lab" / "aegis-gate"
BASH = shutil.which("bash")


@unittest.skipUnless(BASH and os.name != "nt", "needs bash")
class GateFirewallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.state = root / "blocked"
        self.state.write_text("")
        self.log = root / "gate.log"
        binds = root / "bin"
        binds.mkdir()
        # nft: a tiny in-file set (the file comes from $AEGIS_TEST_STATE), so block / unblock /
        # status reflect each other. No f-string here - the nft syntax is all braces.
        nft = r"""#!/bin/bash
args="$*"
state="$AEGIS_TEST_STATE"
pick() { sed -E 's/.*\{ (.*) \}/\1/' <<< "$args"; }
case "$args" in
  "list table inet aegis") exit 0 ;;
  "get element inet aegis blocked { "*" }") grep -qxF "$(pick)" "$state" ;;
  "add element inet aegis blocked { "*" }") ip="$(pick)"; grep -qxF "$ip" "$state" || echo "$ip" >> "$state" ;;
  "delete element inet aegis blocked { "*" }") grep -vxF "$(pick)" "$state" > "$state.t" 2>/dev/null || true; mv "$state.t" "$state" 2>/dev/null || true ;;
  *) exit 0 ;;
esac
"""
        (binds / "nft").write_text(nft)
        # ss: report two established connections to the given address, and succeed on -K.
        (binds / "ss").write_text(textwrap.dedent('''\
            #!/bin/bash
            [[ "$*" == *-K* ]] && exit 0
            printf 'State Recv-Q Send-Q Local Peer\\nESTAB 0 0 a b\\nESTAB 0 0 c d\\n'
            '''))
        # ip: this host owns 192.168.56.107 (the victim), so the gate refuses to block itself.
        (binds / "ip").write_text(textwrap.dedent('''\
            #!/bin/bash
            echo "2: eth1    inet 192.168.56.107/24 brd 192.168.56.255 scope global eth1"
            echo "1: lo    inet 127.0.0.1/8 scope host lo"
            '''))
        for name in ("nft", "ss", "ip"):
            (binds / name).chmod(0o755)
        self.bin = binds

    def gate(self, request: str):
        env = dict(os.environ, NFT=str(self.bin / "nft"), SS=str(self.bin / "ss"), IPCMD=str(self.bin / "ip"),
                   AEGIS_TEST_STATE=str(self.state), AEGIS_GATE_LOG=str(self.log),
                   SSH_ORIGINAL_COMMAND=request)
        done = subprocess.run([BASH, str(GATE)], capture_output=True, text=True, env=env, timeout=20)
        return done.returncode, done.stdout.strip()

    def test_block_status_block_and_unblock_reflect_each_other(self):
        code, out = self.gate("block-status 192.168.56.108")
        self.assertEqual((code, out), (0, "ip=192.168.56.108 blocked=no connections=2"))
        code, out = self.gate("block 192.168.56.108")
        self.assertEqual((code, out), (0, "ip=192.168.56.108 blocked=yes connections=2"))
        self.assertEqual(self.gate("block-status 192.168.56.108"),
                         (0, "ip=192.168.56.108 blocked=yes connections=2"))
        self.assertIn("192.168.56.108", self.state.read_text())
        code, out = self.gate("unblock 192.168.56.108")
        self.assertEqual((code, out), (0, "ip=192.168.56.108 blocked=no connections=2"))
        self.assertNotIn("192.168.56.108", self.state.read_text())

    def test_blocking_is_logged(self):
        self.gate("block 192.168.56.108")
        self.assertIn("BLOCKED ip=192.168.56.108", self.log.read_text())

    def test_refusals_never_touch_the_firewall(self):
        cases = {
            "block 192.168.56.105": "protected address",       # the Wazuh manager
            "block 192.168.56.1": "protected address",         # the laptop
            "block 127.0.0.1": "protected address",
            "block 192.168.56.107": "this host's own address", # the victim itself
            "block 10.0.0.9": "lab network",                   # off the host-only subnet
            "block 192.168.56.999": "not an IPv4 address",
            "block 192.168.56.5;reboot": "not an IPv4 address",
            "block notanip": "not an IPv4 address",
            "block 192.168.56.8 extra": "expected:",           # wrong number of words
            "sudo 192.168.56.8": "unknown action",
        }
        for request, expected in cases.items():
            with self.subTest(request=request):
                code, out = self.gate(request)
                self.assertEqual(code, 2)
                self.assertTrue(out.startswith("DENIED"), out)
                self.assertIn(expected, out)
        self.assertEqual(self.state.read_text(), "")  # nothing was ever added

    def test_an_account_verb_is_not_validated_as_an_address(self):
        # 'status <user>' goes down the account path (needs real users); here it just must not be
        # treated as a firewall request. With no such user it fails, but never as "not an IPv4 address".
        code, out = self.gate("status nosuchuser12345")
        self.assertNotIn("IPv4", out)


if __name__ == "__main__":
    unittest.main()
