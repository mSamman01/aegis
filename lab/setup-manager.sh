#!/bin/bash
# setup-manager.sh - give Aegis a read-only live feed of the manager's alerts.
# Run once, on the Wazuh manager, from the folder holding aegis-feed:
#
#     sudo bash setup-manager.sh "<contents of aegis_feed.pub>"
#
# It creates the account aegis-feed. Its SSH key works only from the laptop
# (192.168.56.1), cannot open a shell, a terminal or a tunnel, and can run one
# thing: /usr/local/sbin/aegis-feed, which only reads the alert files. sudo
# lets aegis-feed run that program, with no arguments, as the owner of the
# alert files - not as root, and nothing else. Membership of the wazuh group
# is not used: that group can read the manager's configuration, agent keys
# included.
set -euo pipefail

KEY="${1:-}"
LAPTOP="192.168.56.1"
ALERTS=/var/ossec/logs/alerts/alerts.json
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
[[ "$KEY" == ssh-ed25519\ * ]] || { echo "pass the public key (the line starting with ssh-ed25519) as the first argument"; exit 1; }
[[ -f aegis-feed ]] || { echo "aegis-feed must be in the current folder"; exit 1; }
[[ -x /usr/bin/python3 ]] || { echo "aegis-feed needs /usr/bin/python3, which is not installed"; exit 1; }
[[ -f "$ALERTS" ]] || { echo "$ALERTS not found: is this the Wazuh manager?"; exit 1; }

OWNER="$(stat -c %U "$ALERTS")"
[[ "$OWNER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { echo "unexpected owner of $ALERTS: $OWNER"; exit 1; }
echo "== the alert files belong to: $OWNER (aegis-feed will read them as $OWNER)"
/usr/bin/python3 --version

echo "== installing /usr/local/sbin/aegis-feed"
install -o root -g root -m 0755 aegis-feed /usr/local/sbin/aegis-feed

echo "== account aegis-feed"
id aegis-feed >/dev/null 2>&1 || useradd -m -s /bin/bash -c "Aegis live feed (read-only)" aegis-feed
usermod -p '*' aegis-feed   # no password at all: key login only
install -d -o aegis-feed -g aegis-feed -m 0700 /home/aegis-feed/.ssh
printf 'restrict,from="%s",command="sudo -n -u %s /usr/local/sbin/aegis-feed" %s\n' "$LAPTOP" "$OWNER" "$KEY" \
    > /home/aegis-feed/.ssh/authorized_keys
chown aegis-feed:aegis-feed /home/aegis-feed/.ssh/authorized_keys
chmod 0600 /home/aegis-feed/.ssh/authorized_keys

echo "== sudo rule: aegis-feed may run aegis-feed as $OWNER, without arguments, and nothing else"
cat > /tmp/aegis-feed.sudoers <<RULE
Defaults!/usr/local/sbin/aegis-feed env_keep += "SSH_ORIGINAL_COMMAND"
aegis-feed ALL=($OWNER) NOPASSWD: /usr/local/sbin/aegis-feed ""
RULE
visudo -cf /tmp/aegis-feed.sudoers
install -o root -g root -m 0440 /tmp/aegis-feed.sudoers /etc/sudoers.d/aegis-feed
rm -f /tmp/aegis-feed.sudoers

echo "== self-test (3 seconds): the first line should be a hello"
timeout 3 sudo -u aegis-feed SSH_ORIGINAL_COMMAND="follow now" sudo -n -u "$OWNER" /usr/local/sbin/aegis-feed | head -c 600 || true
echo
echo "== self-test: a request that is not a follow request must be refused"
sudo -u aegis-feed SSH_ORIGINAL_COMMAND="cat /etc/shadow" sudo -n -u "$OWNER" /usr/local/sbin/aegis-feed || true
echo
echo "Done. Test from the laptop (first time: answer 'yes' to the host key, then Ctrl+C):"
echo "  ssh -i \$HOME\\.ssh\\aegis_feed aegis-feed@<this VM's address> follow now"
