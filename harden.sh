#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  sudo -v || exit 1
  exec sudo "$0" "$@"
fi

if command -v pacman >/dev/null 2>&1; then
  pacman -Sy --noconfirm firewalld apparmor apparmor-utils
elif command -v apt-get >/dev/null 2>&1; then
  apt-get update
  apt-get install -y firewalld apparmor apparmor-utils
else
  exit 1
fi

systemctl enable --now apparmor
systemctl enable --now firewalld

cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.randomize_va_space=2
kernel.unprivileged_bpf_disabled=1
kernel.yama.ptrace_scope=1
kernel.sysrq=0

fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.protected_fifos=2
fs.protected_regular=2
fs.suid_dumpable=0

net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2

net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
EOF

sysctl --system

firewall-cmd --set-default-zone=public
firewall-cmd --permanent --zone=public --add-service=ssh
firewall-cmd --permanent --zone=public --add-service=https
firewall-cmd --permanent --zone=public --add-port=853/tcp
firewall-cmd --permanent --zone=public --add-rich-rule='rule protocol value="dccp" drop'
firewall-cmd --permanent --zone=public --add-rich-rule='rule protocol value="sctp" drop'
firewall-cmd --reload

systemctl enable --now systemd-resolved
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

sed -i 's/^#\?DNS=.*/DNS=1.1.1.1/' /etc/systemd/resolved.conf || true
sed -i 's/^#\?FallbackDNS=.*/FallbackDNS=9.9.9.9/' /etc/systemd/resolved.conf || true
sed -i 's/^#\?DNSOverTLS=.*/DNSOverTLS=yes/' /etc/systemd/resolved.conf || true
sed -i 's/^#\?DNSSEC=.*/DNSSEC=yes/' /etc/systemd/resolved.conf || true

systemctl restart systemd-resolved
resolvectl flush-caches

for p in /etc/apparmor.d/usr.sbin.avahi-daemon /etc/apparmor.d/usr.sbin.dnsmasq; do
  [ -f "$p" ] && aa-enforce "$p"
done

