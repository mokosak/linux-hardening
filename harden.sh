#!/usr/bin/env bash
# ============================================================================
#  linux-hardening / harden.sh
#  Opinionated, idempotent Linux hardening for Arch, Debian/Ubuntu, Fedora/RHEL.
#
#  Usage:
#     sudo ./harden.sh [options]
#
#  Options:
#     -h, --help              Show help
#     -n, --dry-run           Print actions, change nothing
#     -y, --yes               Non-interactive (assume yes)
#     -q, --quiet             Suppress non-error output
#     -v, --verbose           Extra logging
#         --check             Audit current state, change nothing
#         --revert <dir>      Restore configs from a backup directory
#         --profile <name>    Apply a preset: minimal | balanced | paranoid
#         --only <a,b,c>      Run only the listed sections
#         --skip <a,b,c>      Skip the listed sections
#         --list              List available sections
#
#  Env:
#     HARDEN_FIREWALL_BACKEND=nftables|firewalld|auto|none
#
#  Sections:
#     packages  sysctl  modules  firewall  dns  apparmor  ssh
#     login     coredump auditd  fail2ban  updates  usbguard
#     banner    accounting aide
# ============================================================================

set -euo pipefail

# ---- defaults --------------------------------------------------------------
DRY_RUN=0
ASSUME_YES=0
QUIET=0
VERBOSE=0
CHECK_ONLY=0
REVERT_DIR=""
PROFILE="balanced"
ONLY_SECTIONS=""
SKIP_SECTIONS=""

ALL_SECTIONS=(packages sysctl modules firewall dns apparmor ssh login coredump auditd fail2ban updates usbguard banner accounting aide)

# profile → sections enabled
declare -A PROFILE_SECTIONS=(
  [minimal]="packages sysctl firewall dns apparmor"
  [balanced]="packages sysctl modules firewall dns apparmor ssh login coredump auditd updates usbguard banner"
  [paranoid]="packages sysctl modules firewall dns apparmor ssh login coredump auditd fail2ban updates usbguard banner accounting aide"
)

BACKUP_ROOT="/var/backups/linux-hardening"
BACKUP_DIR=""
LOG_FILE="/var/log/linux-hardening.log"
FIREWALL_BACKEND="${HARDEN_FIREWALL_BACKEND:-nftables}"

# ---- colors ----------------------------------------------------------------
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ $(tput colors 2>/dev/null || echo 0) -ge 8 ]]; then
  C_RESET=$'\e[0m'; C_DIM=$'\e[2m'; C_BOLD=$'\e[1m'
  C_GRN=$'\e[38;5;46m'; C_CYAN=$'\e[38;5;51m'; C_YEL=$'\e[38;5;220m'
  C_RED=$'\e[38;5;196m'; C_MAG=$'\e[38;5;201m'; C_BLU=$'\e[38;5;75m'
else
  C_RESET=""; C_DIM=""; C_BOLD=""; C_GRN=""; C_CYAN=""; C_YEL=""; C_RED=""; C_MAG=""; C_BLU=""
fi

# ---- logging ---------------------------------------------------------------
log() {
  [[ $QUIET -eq 1 ]] || printf '%s\n' "$*"
  [[ -n "$LOG_FILE" && -w "$LOG_FILE" ]] || return 0
  ( printf '[%(%F %T)T] %s\n' -1 "$*" >> "$LOG_FILE" ) 2>/dev/null || true
}
info()   { log "${C_CYAN}»${C_RESET} $*"; }
ok()     { log "${C_GRN}✓${C_RESET} $*"; }
warn()   { log "${C_YEL}!${C_RESET} $*"; }
err()    { printf '%s\n' "${C_RED}✗${C_RESET} $*" >&2; }
step()   { log ""; log "${C_BOLD}${C_MAG}── $* ──────────────────────────────────────────${C_RESET}"; }
debug()  { [[ $VERBOSE -eq 1 ]] && log "${C_DIM}· $*${C_RESET}" || true; }

banner() {
  [[ $QUIET -eq 1 ]] && return 0
  log ""
  log "${C_BOLD}${C_GRN}  ┌──────────────────────────────────────────────────┐${C_RESET}"
  log "${C_BOLD}${C_GRN}  │${C_RESET}   ${C_BOLD}linux-hardening${C_RESET}   ${C_DIM}·${C_RESET}   opinionated security   ${C_BOLD}${C_GRN}│${C_RESET}"
  log "${C_BOLD}${C_GRN}  └──────────────────────────────────────────────────┘${C_RESET}"
  log "${C_DIM}  apparmor · nftables · sysctl · auditd · dns-over-tls${C_RESET}"
  log ""
}

# ---- core helpers ----------------------------------------------------------
run() {
  debug "run: $*"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "${C_DIM}[dry-run]${C_RESET} $*"
    return 0
  fi
  "$@"
}

require_root() {
  if [[ $EUID -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      info "Escalating with sudo…"
      sudo -v || { err "sudo authentication failed"; exit 1; }
      exec sudo -E "$0" "$@"
    fi
    err "Must run as root."
    exit 1
  fi
}

confirm() {
  [[ $ASSUME_YES -eq 1 ]] && return 0
  local prompt="${1:-Continue?} [y/N] "
  read -r -p "$prompt" ans || return 1
  [[ "$ans" =~ ^[Yy]$ ]]
}

backup_file() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  local rel="${f#/}"
  local dest="$BACKUP_DIR/$rel"
  run mkdir -p "$(dirname "$dest")"
  run cp -a --preserve=all "$f" "$dest" 2>/dev/null || true
  debug "backed up $f → $dest"
}

write_file() {
  local dest="$1"
  local tmp
  tmp=$(mktemp)
  cat > "$tmp"
  if [[ -e "$dest" ]] && cmp -s "$tmp" "$dest"; then
    debug "unchanged: $dest"
    rm -f "$tmp"; return 0
  fi
  backup_file "$dest"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "${C_DIM}[dry-run]${C_RESET} write → $dest"
    rm -f "$tmp"; return 0
  fi
  install -D -m 0644 "$tmp" "$dest"
  rm -f "$tmp"
  ok "wrote $dest"
}

# ---- distro detection ------------------------------------------------------
DISTRO_FAMILY=""    # arch | debian | rhel
PKG_INSTALL=""
PKG_REFRESH=""

detect_distro() {
  if   command -v pacman  >/dev/null 2>&1; then DISTRO_FAMILY="arch";   PKG_REFRESH="pacman -Sy";            PKG_INSTALL="pacman -S --needed --noconfirm"
  elif command -v apt-get >/dev/null 2>&1; then DISTRO_FAMILY="debian"; PKG_REFRESH="apt-get update";        PKG_INSTALL="apt-get install -y"
  elif command -v dnf     >/dev/null 2>&1; then DISTRO_FAMILY="rhel";   PKG_REFRESH="dnf makecache";         PKG_INSTALL="dnf install -y"
  else
    err "Unsupported distribution (no pacman/apt-get/dnf)."
    exit 1
  fi
  ok "distro family: $DISTRO_FAMILY"
}

pkg_map() {
  # normalize names across distros
  local name="$1"
  case "$DISTRO_FAMILY:$name" in
    arch:apparmor-utils)      echo "apparmor" ;;
    debian:apparmor)          echo "apparmor apparmor-utils apparmor-profiles" ;;
    rhel:apparmor|rhel:apparmor-utils) echo "" ;;   # RHEL uses SELinux, skip silently
    *:nftables)               echo "nftables" ;;
    arch:fail2ban)            echo "fail2ban" ;;
    debian:fail2ban|rhel:fail2ban) echo "fail2ban" ;;
    *:libpwquality)           [[ $DISTRO_FAMILY == debian ]] && echo "libpam-pwquality" || echo "libpwquality" ;;
    *)                        echo "$name" ;;
  esac
}

selected_firewall_backend() {
  case "$FIREWALL_BACKEND" in
    nft|nftables) echo "nftables" ;;
    firewalld)    echo "firewalld" ;;
    none|off)     echo "none" ;;
    auto)
      if command -v nft >/dev/null 2>&1; then
        echo "nftables"
      elif command -v firewall-cmd >/dev/null 2>&1; then
        echo "firewalld"
      else
        echo "nftables"
      fi
      ;;
    *)
      warn "unknown HARDEN_FIREWALL_BACKEND=$FIREWALL_BACKEND; using nftables"
      echo "nftables"
      ;;
  esac
}

pkg_install() {
  local pkgs=()
  for p in "$@"; do
    local mapped; mapped=$(pkg_map "$p")
    [[ -z "$mapped" ]] && continue
    pkgs+=($mapped)
  done
  [[ ${#pkgs[@]} -eq 0 ]] && return 0
  run bash -c "$PKG_INSTALL ${pkgs[*]}"
}

# ---- sections enabled? ------------------------------------------------------
is_enabled() {
  local s="$1"
  local sections="${PROFILE_SECTIONS[$PROFILE]:-}"
  [[ -n "$ONLY_SECTIONS" ]] && sections="${ONLY_SECTIONS//,/ }"
  local wanted=0
  for x in $sections; do [[ "$x" == "$s" ]] && wanted=1; done
  [[ $wanted -eq 0 ]] && return 1
  for x in ${SKIP_SECTIONS//,/ }; do [[ "$x" == "$s" ]] && return 1; done
  return 0
}

# ============================================================================
#  SECTIONS
# ============================================================================

section_packages() {
  is_enabled packages || return 0
  step "Package installation"
  run bash -c "$PKG_REFRESH"
  case "$(selected_firewall_backend)" in
    nftables)  pkg_install nftables ;;
    firewalld) pkg_install firewalld ;;
    none)      debug "firewall package install skipped" ;;
  esac
  if [[ $DISTRO_FAMILY != rhel ]]; then pkg_install apparmor; fi
  case "$(selected_firewall_backend)" in
    nftables)  run systemctl enable --now nftables 2>/dev/null || warn "nftables failed to start (container?)" ;;
    firewalld) run systemctl enable --now firewalld 2>/dev/null || warn "firewalld failed to start (container?)" ;;
  esac
  [[ $DISTRO_FAMILY != rhel ]] && { run systemctl enable --now apparmor 2>/dev/null || true; }
}

section_sysctl() {
  is_enabled sysctl || return 0
  step "Kernel & network sysctl"
  write_file /etc/sysctl.d/99-hardening.conf <<'EOF'
# Managed by linux-hardening/harden.sh — edit with care.

# ── Kernel self-protection ──────────────────────────────────────────────
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.printk=3 3 3 3
kernel.kexec_load_disabled=1
kernel.unprivileged_bpf_disabled=1
kernel.yama.ptrace_scope=2
kernel.sysrq=0
kernel.perf_event_paranoid=3
kernel.randomize_va_space=2
kernel.unprivileged_userns_clone=0
kernel.core_uses_pid=1
dev.tty.ldisc_autoload=0

# ── Filesystem safety ───────────────────────────────────────────────────
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.protected_fifos=2
fs.protected_regular=2
fs.suid_dumpable=0

# ── IPv4 network stack ──────────────────────────────────────────────────
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.ip_forward=0
net.ipv4.tcp_timestamps=0
net.ipv4.tcp_sack=0
net.ipv4.tcp_dsack=0
net.ipv4.tcp_fack=0

# ── IPv6 network stack ──────────────────────────────────────────────────
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.forwarding=0
EOF
  run sysctl --system >/dev/null || warn "sysctl --system reported errors"
}

section_modules() {
  is_enabled modules || return 0
  step "Blacklist obsolete / risky kernel modules"
  write_file /etc/modprobe.d/99-hardening.conf <<'EOF'
# Obscure / rarely-used network protocols (attack surface)
install dccp    /bin/false
install sctp    /bin/false
install rds     /bin/false
install tipc    /bin/false
install n-hdlc  /bin/false
install ax25    /bin/false
install netrom  /bin/false
install x25     /bin/false
install rose    /bin/false
install decnet  /bin/false
install econet  /bin/false
install af_802154 /bin/false
install ipx     /bin/false
install appletalk /bin/false
install psnap   /bin/false
install p8023   /bin/false
install p8022   /bin/false
install can     /bin/false
install atm     /bin/false

# Obsolete or niche filesystems
install cramfs  /bin/false
install freevxfs /bin/false
install jffs2   /bin/false
install hfs     /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf     /bin/false

# DMA-attack prone interfaces
install firewire-core /bin/false
install firewire-ohci /bin/false
install firewire-sbp2 /bin/false
install thunderbolt   /bin/false
EOF
}

section_firewall() {
  is_enabled firewall || return 0
  case "$(selected_firewall_backend)" in
    nftables)
      step "Firewall (nftables, default-deny inbound)"
      command -v nft >/dev/null 2>&1 || { warn "nft missing; skipping"; return 0; }
      write_file /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
# Managed by linux-hardening/harden.sh

flush ruleset

table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;

    ct state invalid drop
    ct state established,related accept
    iifname "lo" accept

    # Keep DHCP and ICMP/ICMPv6 working; otherwise IPv6 and some networks break.
    udp sport 67 udp dport 68 accept
    udp sport 547 udp dport 546 accept
    meta l4proto icmp accept
    meta l4proto ipv6-icmp accept

    # Public services this script intentionally leaves reachable.
    tcp dport 22 ct state new limit rate 3/minute accept
    tcp dport 443 accept
    tcp dport 853 accept
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
  }

  chain output {
    type filter hook output priority filter; policy accept;

    # Cut off rarely-needed protocols at the firewall too.
    meta l4proto { dccp, sctp } drop
  }
}
EOF
      run nft -f /etc/nftables.conf
      run systemctl enable --now nftables 2>/dev/null || true
      ;;
    firewalld)
      step "Firewall (firewalld, default-deny inbound)"
      command -v firewall-cmd >/dev/null 2>&1 || { warn "firewall-cmd missing; skipping"; return 0; }
      run firewall-cmd --set-default-zone=public >/dev/null
      run firewall-cmd --permanent --zone=public --set-target=DROP >/dev/null || true
      run firewall-cmd --permanent --zone=public --add-service=ssh
      run firewall-cmd --permanent --zone=public --add-service=https
      run firewall-cmd --permanent --zone=public --add-port=853/tcp
      run firewall-cmd --permanent --zone=public --add-rich-rule='rule protocol value="dccp" drop' 2>/dev/null || true
      run firewall-cmd --permanent --zone=public --add-rich-rule='rule protocol value="sctp" drop' 2>/dev/null || true
      run firewall-cmd --permanent --zone=public --add-rich-rule='rule service name="ssh" limit value="3/m" accept' 2>/dev/null || true
      run firewall-cmd --reload >/dev/null
      ;;
    none)
      warn "firewall backend disabled; skipping firewall rules"
      ;;
  esac
}

section_dns() {
  is_enabled dns || return 0
  step "Encrypted DNS (systemd-resolved + DoT + DNSSEC)"
  command -v resolvectl >/dev/null 2>&1 || { warn "systemd-resolved missing; skipping"; return 0; }
  run systemctl enable --now systemd-resolved
  run ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
  if [[ -f /etc/systemd/resolved.conf ]]; then
    backup_file /etc/systemd/resolved.conf
    write_file /etc/systemd/resolved.conf.d/hardening.conf <<'EOF'
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com
FallbackDNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net
DNSOverTLS=yes
DNSSEC=yes
Cache=yes
DNSStubListener=yes
ReadEtcHosts=yes
EOF
  fi
  run systemctl restart systemd-resolved
  run resolvectl flush-caches 2>/dev/null || true
}

section_apparmor() {
  is_enabled apparmor || return 0
  [[ $DISTRO_FAMILY == rhel ]] && { warn "skipping apparmor on RHEL family (SELinux recommended)"; return 0; }
  step "AppArmor profile enforcement"
  command -v aa-enforce >/dev/null 2>&1 || { warn "aa-enforce missing; skipping"; return 0; }
  for p in /etc/apparmor.d/usr.sbin.avahi-daemon \
           /etc/apparmor.d/usr.sbin.dnsmasq \
           /etc/apparmor.d/usr.sbin.cups-browsed \
           /etc/apparmor.d/usr.bin.firefox \
           /etc/apparmor.d/usr.bin.thunderbird; do
    [[ -f "$p" ]] && run aa-enforce "$p" 2>/dev/null || true
  done
}

section_ssh() {
  is_enabled ssh || return 0
  [[ -f /etc/ssh/sshd_config ]] || { debug "sshd not installed"; return 0; }
  step "SSH daemon hardening"
  backup_file /etc/ssh/sshd_config
  write_file /etc/ssh/sshd_config.d/99-hardening.conf <<'EOF'
# Managed by linux-hardening/harden.sh
Protocol 2
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 4
LogLevel VERBOSE
Banner /etc/issue.net
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
EOF
  run systemctl reload sshd 2>/dev/null || run systemctl reload ssh 2>/dev/null || warn "could not reload sshd"
}

section_login() {
  is_enabled login || return 0
  step "Login & password policy"
  pkg_install libpwquality || true
  if [[ -f /etc/login.defs ]]; then
    backup_file /etc/login.defs
    for pair in "PASS_MAX_DAYS 180" "PASS_MIN_DAYS 1" "PASS_WARN_AGE 14" "UMASK 027" "ENCRYPT_METHOD YESCRYPT" "LOGIN_RETRIES 3" "LOGIN_TIMEOUT 60"; do
      key="${pair% *}"; val="${pair#* }"
      if grep -qE "^#?\s*${key}\b" /etc/login.defs; then
        run sed -i -E "s|^#?\s*${key}\s+.*|${key}\t${val}|" /etc/login.defs
      else
        run bash -c "printf '%s\t%s\n' '$key' '$val' >> /etc/login.defs"
      fi
    done
  fi
  # faillock / pam_faillock defaults
  if [[ -f /etc/security/faillock.conf ]]; then
    backup_file /etc/security/faillock.conf
    run sed -i -E 's|^#?\s*deny\s*=.*|deny = 5|'           /etc/security/faillock.conf
    run sed -i -E 's|^#?\s*unlock_time\s*=.*|unlock_time = 900|' /etc/security/faillock.conf
  fi
  # pwquality
  if [[ -f /etc/security/pwquality.conf ]]; then
    backup_file /etc/security/pwquality.conf
    write_file /etc/security/pwquality.conf <<'EOF'
minlen = 12
minclass = 3
maxrepeat = 3
maxsequence = 3
dictcheck = 1
usercheck = 1
enforce_for_root
EOF
  fi
}

section_coredump() {
  is_enabled coredump || return 0
  step "Disable core dumps"
  write_file /etc/security/limits.d/99-hardening.conf <<'EOF'
* hard core 0
* soft core 0
EOF
  if [[ -d /etc/systemd/coredump.conf.d ]] || [[ -f /etc/systemd/coredump.conf ]]; then
    write_file /etc/systemd/coredump.conf.d/hardening.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
  fi
}

section_auditd() {
  is_enabled auditd || return 0
  step "Auditd syscall auditing"
  pkg_install audit 2>/dev/null || pkg_install auditd 2>/dev/null || warn "audit package not found"
  if [[ -d /etc/audit/rules.d ]]; then
    local tmp
    tmp=$(mktemp)
    cat > "$tmp" <<'EOF'
## linux-hardening/harden.sh audit baseline
-D
-b 8192
-f 1

# Identity, authentication
-w /etc/passwd       -p wa -k identity
-w /etc/shadow       -p wa -k identity
-w /etc/group        -p wa -k identity
-w /etc/gshadow      -p wa -k identity
-w /etc/sudoers      -p wa -k sudoers
-w /etc/sudoers.d/   -p wa -k sudoers
-w /var/log/faillog  -p wa -k logins
-w /var/log/lastlog  -p wa -k logins
-w /var/run/utmp     -p wa -k logins

# Kernel module loading
-w /sbin/insmod   -p x -k modules
-w /sbin/rmmod    -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module,finit_module -k modules

# Privilege escalation
-w /usr/bin/sudo  -p x -k privileged
-w /usr/bin/su    -p x -k privileged
-w /usr/bin/pkexec -p x -k privileged
EOF
    add_audit_watch() {
      local path="$1" perms="$2" key="$3"
      [[ -e "$path" ]] && printf -- '-w %s -p %s -k %s\n' "$path" "$perms" "$key" >> "$tmp"
    }

    add_audit_watch /etc/localtime wa time
    add_audit_watch /etc/hosts wa network
    add_audit_watch /etc/resolv.conf wa network
    add_audit_watch /etc/ssh/sshd_config wa sshd
    add_audit_watch /etc/ssh/sshd_config.d/ wa sshd
    add_audit_watch /boot/ wa boot
    add_audit_watch /etc/kernel/cmdline wa boot
    add_audit_watch /etc/mkinitcpio.conf wa boot
    add_audit_watch /etc/mkinitcpio.d/ wa boot
    add_audit_watch /usr/share/secureboot/ wa secureboot
    add_audit_watch /var/lib/sbctl/ wa secureboot
    add_audit_watch /etc/crypttab wa luks
    add_audit_watch /etc/nftables.conf wa firewall
    add_audit_watch /etc/firewalld/ wa firewall
    add_audit_watch /etc/usbguard/ wa usbguard
    add_audit_watch /etc/apparmor.d/ wa apparmor
    add_audit_watch /etc/modprobe.d/ wa modules
    add_audit_watch /etc/systemd/ wa systemd
    add_audit_watch /usr/lib/systemd/system/ wa systemd

    write_file /etc/audit/rules.d/99-hardening.rules < "$tmp"
    rm -f "$tmp"
    run augenrules --load 2>/dev/null || true
  fi
  run systemctl enable --now auditd 2>/dev/null || true
}

section_fail2ban() {
  is_enabled fail2ban || return 0
  step "Fail2ban"
  pkg_install fail2ban || return 0
  write_file /etc/fail2ban/jail.d/hardening.local <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd

[sshd]
enabled = true
EOF
  run systemctl enable --now fail2ban 2>/dev/null || true
}

section_updates() {
  is_enabled updates || return 0
  step "Automatic security updates"
  case "$DISTRO_FAMILY" in
    debian)
      pkg_install unattended-upgrades apt-listchanges || true
      run dpkg-reconfigure -f noninteractive unattended-upgrades 2>/dev/null || true
      ;;
    arch)
      # nothing to auto-upgrade safely on Arch; instead clean old caches
      pkg_install pacman-contrib || true
      run systemctl enable --now paccache.timer 2>/dev/null || true
      ;;
    rhel)
      pkg_install dnf-automatic || true
      run systemctl enable --now dnf-automatic.timer 2>/dev/null || true
      ;;
  esac
}

section_usbguard() {
  is_enabled usbguard || return 0
  step "USBGuard (USB device whitelisting)"
  pkg_install usbguard || return 0
  if [[ ! -f /etc/usbguard/rules.conf ]] || [[ ! -s /etc/usbguard/rules.conf ]]; then
    run bash -c 'usbguard generate-policy > /etc/usbguard/rules.conf 2>/dev/null || true'
    run chmod 0600 /etc/usbguard/rules.conf 2>/dev/null || true
  fi
  run systemctl enable --now usbguard 2>/dev/null || true
  warn "USBGuard enabled — review /etc/usbguard/rules.conf before rebooting."
}

section_banner() {
  is_enabled banner || return 0
  step "Legal login banner"
  local msg="Authorized use only. All activity may be monitored and reported."
  write_file /etc/issue      <<< "$msg"
  write_file /etc/issue.net  <<< "$msg"
  write_file /etc/motd       <<< "$msg"
}

section_accounting() {
  is_enabled accounting || return 0
  step "Process accounting"
  pkg_install acct 2>/dev/null || pkg_install psacct 2>/dev/null || warn "no acct package available"
  run systemctl enable --now acct 2>/dev/null || run systemctl enable --now psacct 2>/dev/null || true
}

section_aide() {
  is_enabled aide || return 0
  step "AIDE file integrity (initial DB — slow)"
  pkg_install aide || return 0
  if [[ ! -f /var/lib/aide/aide.db.gz ]] && [[ ! -f /var/lib/aide/aide.db ]]; then
    if confirm "Initialize AIDE database now (can take several minutes)?"; then
      run aideinit 2>/dev/null || run aide --init
      [[ -f /var/lib/aide/aide.db.new.gz ]] && run mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    else
      warn "AIDE installed but DB not initialized. Run 'aideinit' later."
    fi
  fi
}

# ============================================================================
#  AUDIT MODE
# ============================================================================

audit_report() {
  banner
  step "Audit: current hardening state"
  local rows=()
  _chk() {
    local label="$1" cond="$2"
    local mark="${C_RED}✗${C_RESET}"
    if eval "$cond" >/dev/null 2>&1; then mark="${C_GRN}✓${C_RESET}"; fi
    printf '  %b  %s\n' "$mark" "$label"
  }
  _chk "firewall backend configured"        "systemctl is-active --quiet firewalld || systemctl is-active --quiet nftables || systemctl is-enabled --quiet nftables"
  _chk "apparmor enabled"                   "systemctl is-active --quiet apparmor || aa-status --enabled"
  _chk "systemd-resolved running"           "systemctl is-active --quiet systemd-resolved"
  _chk "DNSOverTLS enabled"                 "resolvectl status 2>/dev/null | grep -qi 'DNSOverTLS: yes\\|DNSOverTLS=yes'"
  _chk "auditd running"                     "systemctl is-active --quiet auditd"
  _chk "fail2ban running"                   "systemctl is-active --quiet fail2ban"
  _chk "usbguard running"                   "systemctl is-active --quiet usbguard"
  _chk "sysctl hardening file present"      "[ -f /etc/sysctl.d/99-hardening.conf ] || grep -Rqs 'kernel.kptr_restrict' /etc/sysctl.d /usr/lib/sysctl.d"
  _chk "kptr_restrict == 2"                 "[ \"$(sysctl -n kernel.kptr_restrict 2>/dev/null)\" = 2 ]"
  _chk "ptrace_scope >= 1"                  "[ \"$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)\" -ge 1 ]"
  _chk "SYN cookies on"                     "[ \"$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)\" = 1 ]"
  _chk "IP forwarding off"                  "[ \"$(sysctl -n net.ipv4.ip_forward 2>/dev/null)\" = 0 ]"
  _chk "dccp/sctp blacklisted"              "grep -q 'install dccp' /etc/modprobe.d/*.conf /usr/lib/modprobe.d/*.conf 2>/dev/null && grep -q 'install sctp' /etc/modprobe.d/*.conf /usr/lib/modprobe.d/*.conf 2>/dev/null"
  _chk "root login over ssh disabled"       "grep -qiE '^PermitRootLogin\\s+no' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
  _chk "password auth over ssh disabled"    "grep -qiE '^PasswordAuthentication\\s+no' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null"
  _chk "core dumps disabled"                "[ \"$(sysctl -n fs.suid_dumpable 2>/dev/null)\" = 0 ]"
  _chk "audit tamper rules present"          "grep -Rqs 'boot\\|secureboot\\|usbguard\\|apparmor\\|privileged' /etc/audit/rules.d"
  _chk "legal banner present"               "[ -s /etc/issue.net ]"
}

# ============================================================================
#  REVERT
# ============================================================================

do_revert() {
  local dir="$1"
  [[ -d "$dir" ]] || { err "backup dir not found: $dir"; exit 1; }
  banner
  step "Revert from $dir"
  confirm "Restore every file under $dir back to /? This will overwrite current configs." || { warn "aborted"; exit 1; }
  (cd "$dir" && find . -type f -print0 | while IFS= read -r -d '' f; do
    local target="/${f#./}"
    run install -D -m 0644 "$dir/${f#./}" "$target"
    ok "restored $target"
  done)
  info "Revert complete. You may want to run: sysctl --system && systemctl daemon-reload"
}

# ============================================================================
#  ARG PARSING
# ============================================================================

usage() { sed -n '2,26p' "$0"; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)    usage; exit 0 ;;
      -n|--dry-run) DRY_RUN=1 ;;
      -y|--yes)     ASSUME_YES=1 ;;
      -q|--quiet)   QUIET=1 ;;
      -v|--verbose) VERBOSE=1 ;;
      --check)      CHECK_ONLY=1 ;;
      --revert)     shift; REVERT_DIR="${1:-}" ;;
      --profile)    shift; PROFILE="${1:-balanced}" ;;
      --only)       shift; ONLY_SECTIONS="${1:-}" ;;
      --skip)       shift; SKIP_SECTIONS="${1:-}" ;;
      --list)       printf '%s\n' "${ALL_SECTIONS[@]}"; exit 0 ;;
      *) err "unknown option: $1"; usage; exit 2 ;;
    esac
    shift
  done
  [[ -n "${PROFILE_SECTIONS[$PROFILE]:-}" ]] || { err "unknown profile: $PROFILE"; exit 2; }
}

# ============================================================================
#  MAIN
# ============================================================================

main() {
  parse_args "$@"

  if [[ $CHECK_ONLY -eq 1 ]]; then
    audit_report
    exit 0
  fi

  [[ $DRY_RUN -eq 0 ]] && require_root "$@"
  ( mkdir -p "$(dirname "$LOG_FILE")" ) 2>/dev/null || true
  ( : > "$LOG_FILE" ) 2>/dev/null || LOG_FILE=""

  if [[ -n "$REVERT_DIR" ]]; then
    do_revert "$REVERT_DIR"
    exit 0
  fi

  banner
  detect_distro

  BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
  run mkdir -p "$BACKUP_DIR"
  info "profile: ${C_BOLD}${PROFILE}${C_RESET}"
  info "backup:  $BACKUP_DIR"
  info "log:     $LOG_FILE"
  [[ $DRY_RUN -eq 1 ]] && warn "dry-run: no changes will be made"

  for s in "${ALL_SECTIONS[@]}"; do
    "section_${s}" || { err "section $s failed"; exit 1; }
  done

  step "Summary"
  ok "hardening run complete"
  info "reboot recommended (for module blacklists & sysctl to fully apply)"
  info "revert with:  sudo $0 --revert $BACKUP_DIR"
}

main "$@"
