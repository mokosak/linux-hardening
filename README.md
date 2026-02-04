Linux Hardening Script (AppArmor + Firewalld)

This is a small, opinionated Linux hardening script for people who want real security improvements without turning their system into an unusable science experiment.

It focuses on:
- Kernel hardening
- Network hardening
- Mandatory access control
- Secure DNS
- Reasonable defaults

No CIS checkbox chasing. No distro lock-in. No magic.

--------------------------------------------------

Why this exists

Most Linux systems ship functional, not secure.

This script applies a set of changes that:
- Reduce information leaks
- Shrink attack surface
- Make exploitation harder
- Add meaningful containment if something does get compromised

Everything here is stuff you’d likely end up doing manually anyway if you hardened systems long enough.

--------------------------------------------------

What systems this works on

The script automatically detects the distro family.

Debian / Ubuntu systems use apt.
Arch Linux systems use pacman.

If neither is detected, the script exits without making changes.

No guessing. No partial installs.

--------------------------------------------------

How privileges are handled

The script does not assume root access.

If you run it as a normal user:
- It asks for sudo once at startup
- If sudo fails or is unavailable, execution stops
- After elevation, the script re-execs itself as root

This avoids half-applied configurations and silent failures.

--------------------------------------------------

What the script actually does

Mandatory access control (AppArmor)

AppArmor is installed, enabled at boot, and enforced.

If profiles for common services such as avahi-daemon or dnsmasq exist, they are explicitly switched into enforce mode.

Why this matters:
Even if a service is exploited, AppArmor limits what it can access.
You get containment instead of full system compromise.

This is one of the highest-value security controls on Linux and is often left unused.

--------------------------------------------------

Kernel hardening (sysctl)

A hardened sysctl profile is written to /etc/sysctl.d/99-hardening.conf and applied immediately.

It covers three main areas.

Kernel self-protection:
- Hides kernel pointers
- Restricts access to dmesg
- Enables full ASLR
- Disables unprivileged BPF
- Disables magic SysRq

This reduces information leaks and limits kernel abuse by local attackers.

Process and filesystem safety:
- Blocks hardlink and symlink attacks
- Protects FIFOs and regular files
- Disables SUID core dumps
- Restricts ptrace between processes

This shuts down a large class of local privilege escalation techniques.

Network stack hardening:
- Disables ICMP redirects and source routing
- Enables TCP SYN cookies
- Enables reverse path filtering
- Filters bogus ICMP responses
- Applies sane IPv6 defaults

These settings make common network attacks significantly harder.

--------------------------------------------------

Firewall configuration (Firewalld)

Firewalld is installed, enabled, and configured with a default-deny posture.

Allowed traffic:
- SSH
- HTTPS
- DNS-over-TLS (TCP port 853)

Explicitly blocked protocols:
- DCCP
- SCTP

These protocols are rarely needed on general-purpose systems and only increase attack surface.

All rules are permanent and survive reboots.

--------------------------------------------------

DNS security

The script enables and configures systemd-resolved with:
- DNS-over-TLS
- DNSSEC validation
- Explicit trusted resolvers
- Secure fallback resolvers

It also locks /etc/resolv.conf to the systemd stub to prevent other software from silently replacing it.

Why this matters:
It prevents DNS spoofing and downgrade attacks, and stops random software from hijacking name resolution.

--------------------------------------------------

What this script intentionally does not do

This script does not:
- Modify the bootloader
- Change kernel command line parameters
- Disable IPv6
- Alter SSH configuration or ports
- Remove services automatically
- Attempt CIS, STIG, or government compliance

Those decisions are environment-specific and should be made consciously.

--------------------------------------------------

Is this safe to run?

On most desktops, laptops, and light servers, yes.

That said:
Read the script.
Understand what it changes.
Do not run it blindly on systems you do not control.

Security always involves trade-offs.

--------------------------------------------------

Recommended next steps (optional)

If you want to go further:
- Enable AppArmor at boot via kernel parameters
- Increase kernel.yama.ptrace_scope on non-development systems
- Mask unused services such as avahi, cups, or rpcbind
- Add SSH rate limiting via firewalld
- Deploy auditd for syscall auditing
- Combine with disk encryption and secure boot

This script is a foundation, not the finish line.

--------------------------------------------------

CREDITS

Most of this documentation was possible by reading a well done privacy guide explaining sysctl and boot parameters.

```
https://theprivacyguide1.github.io/linux_hardening_guide#sysctl
```
