# linux-hardening

A hardening script for Linux that actually gets used, because nobody wants to
read a 400-line STIG checklist at 2am.

Point it at an Arch, Debian/Ubuntu, or Fedora box. It makes the kernel pickier,
the network quieter, SSH stricter, DNS encrypted, and AppArmor actually enforce.
You can dry-run everything first, every change gets backed up, and if you hate
the result you can roll the whole thing back with one command.

There's also a browser-based builder — `hardening-gui.html` — that lets you
tick what you want and spits out a custom script.

---

## Try it in 30 seconds

```sh
git clone https://github.com/mokosak/linux-hardening
cd linux-hardening

# see what it *would* do, no changes:
./harden.sh --dry-run

# audit the current state of your system:
./harden.sh --check

# when you're ready:
sudo ./harden.sh
```

That's it. Default profile is `balanced`, which is sane for laptops, desktops,
and most servers.

---

## Three profiles, pick one

**`minimal`** — the classics. Kernel sysctl, firewall, AppArmor, encrypted DNS.
Nothing that's going to break your workflow.

**`balanced`** *(default)* — minimal, plus SSH hardening, password policy,
auditd, module blacklist, a legal banner, and automatic security updates.
This is the one you probably want.

**`paranoid`** — everything above, plus fail2ban, USBGuard, AIDE file
integrity, and process accounting. Great for servers. Annoying on a laptop
that you plug random USB devices into.

```sh
sudo ./harden.sh --profile paranoid -y
```

You can also cherry-pick:

```sh
sudo ./harden.sh --only firewall,dns,ssh
sudo ./harden.sh --skip usbguard,aide
./harden.sh --list          # show every section name
```

---

## What actually gets touched

| area       | what happens |
|------------|--------------|
| **kernel** | kptr_restrict, dmesg_restrict, ASLR, ptrace_scope, SysRq off, BPF locked down, kexec disabled, and a few dozen more knobs in `/etc/sysctl.d/99-hardening.conf` |
| **network** | SYN cookies, rp_filter, no ICMP redirects, no source routing, IPv6 hardened instead of disabled, forwarding off, martians logged |
| **modules** | obsolete protocols (dccp, sctp, rds, tipc, decnet…), obscure filesystems (cramfs, hfs, udf…), and firewire/thunderbolt all blacklisted |
| **firewall** | firewalld with default-deny, SSH rate-limited to 3/min, DCCP/SCTP dropped, only SSH/HTTPS/DoT allowed out of the box |
| **dns** | systemd-resolved with DNS-over-TLS (Cloudflare + Quad9 fallback) and DNSSEC |
| **apparmor** | enforce profiles for avahi, dnsmasq, cups-browsed, firefox, thunderbird when present |
| **ssh** | key-only, no root, modern crypto suites, short timeouts, pre-auth banner, dropped into `sshd_config.d/` so it doesn't fight with distro defaults |
| **login** | `login.defs`, `pwquality` (12+ chars, 3 classes, dict check), `faillock` lockout, yescrypt hashing |
| **dumps** | core dumps off everywhere: ulimit, setuid, systemd-coredump |
| **auditd** | baseline rules for identity files, sudoers, sshd config, module loading |
| **updates** | unattended-upgrades / dnf-automatic / paccache on the right distro |
| **extras** | legal banner, fail2ban, USBGuard, AIDE, process accounting (paranoid only) |

Every section is a function in the script. Open it up, read it, disable what
you don't want. No magic.

---

## It won't break your machine (probably)

A few things are worth calling out:

- **Every file it edits gets backed up** to
  `/var/backups/linux-hardening/<timestamp>/`. Nothing is overwritten without a
  copy saved first.

- **`--dry-run` shows you exactly what would happen.** Prefix every command
  with `[dry-run]` and no files touched. Run this before the real thing.

- **Rollback is one command:**

  ```sh
  sudo ./harden.sh --revert /var/backups/linux-hardening/20260418-214032
  ```

- **It's idempotent.** Run it ten times, nothing changes after the first. If
  files already match, they're left alone.

- **`--check` is read-only.** Runs through every setting and prints a
  pass/fail table. Useful for auditing machines you haven't hardened yet, or
  verifying the script did what it claimed.

- Everything gets logged to `/var/log/linux-hardening.log`.

---

## Things it deliberately won't do

- **Touch the bootloader or kernel command line.** Those decisions depend on
  your hardware and what you boot with. Add kernel params yourself.
- **Disable IPv6.** It's 2026. The script hardens IPv6 instead of pretending
  it doesn't exist.
- **Change your SSH port** or pretend that's real security.
- **Chase CIS / STIG / FedRAMP compliance.** Those are political artifacts,
  not security.
- **Reconfigure your users.** Passwords, shells, groups — your call.

---

## The web UI

Open `hardening-gui.html` in any browser. No build step, no server, no
dependencies. It's one file.

You get:

- **Three presets** (minimal/balanced/paranoid) as one-click buttons
- **Search** across every option — type "ssh" or "dns" or "ipv6"
- **Four themes** if you care about that sort of thing (cyber, synthwave,
  matrix, nord)
- **Live script preview** — syntax-highlighted bash that updates as you toggle
- **Stats** — line count, byte size, "hardness score"
- **Import/export** your toggle state as JSON so you can reuse configs across
  machines
- **Keyboard shortcuts**: `Ctrl+F` to search, `Ctrl+S` to download,
  `Ctrl+Shift+C` to copy

Hit **Download**, scp it to the box, run it as root.

---

## Under the hood

The script is one bash file. It's ~700 lines but most of that is the sysctl,
SSH, and auditd config blobs being emitted verbatim. The actual logic is small:

- distro detection (`pacman` / `apt-get` / `dnf`)
- a `run` wrapper that either executes or prints (dry-run)
- a `write_file` helper that backs up before writing and skips unchanged files
- one function per section, called from `main` based on the profile

If you want to add a section, grep for `section_banner` and copy the pattern.

---

## Why this exists

Most Linux distros ship functional, not secure. The defaults assume you're on
a trusted network running trusted software, and half the useful security
machinery (AppArmor, sysctl, auditd, faillock) is installed but not really
turned on.

This script does the things you'd end up doing by hand anyway if you hardened
enough systems — nothing exotic, nothing bleeding-edge. The goal is a box
that's meaningfully harder to exploit and mostly indistinguishable from
normal for the user.

Opinionated defaults. Read before running. Ship it.

---

## Credits

Sysctl recommendations cribbed from
[theprivacyguide1.github.io/linux_hardening_guide](https://theprivacyguide1.github.io/linux_hardening_guide)
and the kernel self-protection project. Everything else is just years of
running `diff /etc/` against fresh installs.
