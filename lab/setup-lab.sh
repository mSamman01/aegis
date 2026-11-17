#!/bin/bash
# setup-lab.sh - prepare the lab VM for Aegis. Run once, on the lab VM:
#
#     sudo bash setup-lab.sh "<contents of aegis_lab.pub>"
#
# It creates:
#   svc_backup  - the account the lab attack will guess (you choose a weak password)
#   aegis-exec  - the account Aegis connects as; its SSH key can only run aegis-gate,
#                 only from the laptop (192.168.56.1), and sudo allows nothing else
set -euo pipefail

KEY="${1:-}"
LAPTOP="192.168.56.1"
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
[[ "$KEY" == ssh-ed25519\ * ]] || { echo "pass the public key (the line starting with ssh-ed25519) as the first argument"; exit 1; }
[[ -f aegis-gate ]] || { echo "aegis-gate must be in the current folder"; exit 1; }

echo "== installing /usr/local/sbin/aegis-gate"
install -o root -g root -m 0755 aegis-gate /usr/local/sbin/aegis-gate
touch /var/log/aegis-gate.log && chmod 0640 /var/log/aegis-gate.log

echo "== account aegis-exec"
id aegis-exec >/dev/null 2>&1 || useradd -m -s /bin/bash -c "Aegis executor" aegis-exec
usermod -p '*' aegis-exec   # no password at all: key login only
install -d -o aegis-exec -g aegis-exec -m 0700 /home/aegis-exec/.ssh
printf 'restrict,from="%s",command="sudo -n /usr/local/sbin/aegis-gate" %s\n' "$LAPTOP" "$KEY" \
    > /home/aegis-exec/.ssh/authorized_keys
chown aegis-exec:aegis-exec /home/aegis-exec/.ssh/authorized_keys
chmod 0600 /home/aegis-exec/.ssh/authorized_keys

echo "== sudo rule: aegis-exec may run aegis-gate, and nothing else"
cat > /tmp/aegis-gate.sudoers <<'RULE'
Defaults!/usr/local/sbin/aegis-gate env_keep += "SSH_ORIGINAL_COMMAND"
aegis-exec ALL=(root) NOPASSWD: /usr/local/sbin/aegis-gate
RULE
visudo -cf /tmp/aegis-gate.sudoers
install -o root -g root -m 0440 /tmp/aegis-gate.sudoers /etc/sudoers.d/aegis-gate
rm -f /tmp/aegis-gate.sudoers

echo "== account svc_backup (the account the lab attack will guess)"
if ! id svc_backup >/dev/null 2>&1; then
    useradd -m -s /bin/bash -c "Backup service (lab target)" svc_backup
    usermod -aG sudo svc_backup
    echo "Choose a weak password for svc_backup, one you will 'guess' in the attack:"
    passwd svc_backup
fi

echo "== SSH password logins (the attack needs them):"
sshd -T 2>/dev/null | grep -i '^passwordauthentication' || true
echo
echo "Done. Test from the laptop:"
echo "  ssh -i \$HOME\\.ssh\\aegis_lab aegis-exec@<this VM's address> status svc_backup"
