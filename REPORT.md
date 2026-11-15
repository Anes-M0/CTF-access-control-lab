# TP 2: Access Control CTF

> **University of Blida 1**  
> Computer Science Department, 4th year engineering  
> Computer Systems Security, TP 3  
> Lab report, 15 November 2026

## Overview

This lab is a Docker challenge with five flags. Each flag is protected by a different access-control mistake, and the handout asks for the flag value, the path to it, the commands used, and the reason the control failed. This report follows that order. The recorded work was done inside the challenge container with the `student` account (uid 1001).

> The commands shown here stayed inside the challenge container. There is no evidence of a direct root login, host access, Docker socket access, access to another container, password guessing, or a kernel exploit. The `sudo` commands were used only where the lab policy allowed them.

Five flags were recovered:

| Flag | Value |
|---|---|
| Flag 1 | `FLAG{hidden_files_are_not_access_control}` |
| Flag 2 | `FLAG{confused_deputy_reads_for_the_attacker}` |
| Flag 3 | `FLAG{least_privilege_is_not_optional}` |
| Flag 4 | `FLAG{root_should_never_execute_student_writable_code}` |
| Flag 5 | `FLAG{capabilities_can_be_more_precise_than_suid}` |

The optional confused-deputy fix was attempted, but the project contains no passing grader output. That task is covered in the appendix and is not counted as solved.

## Lab environment and method

The `sudo -l` output identifies the host as `b1d7a230795f` and the account as `student`. The shell is bash 5.2. The tools used in the captures are `find`, `ls`, `cat`, `sudo`, `getcap`, and Python. The approach was to enumerate the filesystem and its permissions, read the sudo policy, look for SUID binaries and file capabilities, then test the weakest path to each protected file.

Two reference captures in `Helpful/` record shell handling used during the lab. The first upgrades a limited shell to a PTY. The second sets a readable prompt with colors.

[![PTY upgrade](Helpful/Screenshot%202026-11-15%20140923.png)](Helpful/Screenshot%202026-11-15%20140923.png)

*Upgrading the shell to a PTY with `pty.spawn`.*

[![Prompt configuration](Helpful/Screenshot%202026-11-15%20152616.png)](Helpful/Screenshot%202026-11-15%20152616.png)

*Setting a readable shell prompt with `PS1`.*

## Flag 1: Hidden does not mean protected

This flag's evidence list asks for the flag value, its full path, the discovery command, and the file permissions. The first two are recorded below. The permissions were not captured, which is noted in the evidence gaps.

### Finding the file

```bash
find / -type f -name "*flag*" 2>/dev/null
```

The search started at `/`, so it covered every mounted directory. `-type f` limited the results to regular files, `-name "*flag*"` matched names that contain `flag`, and `2>/dev/null` hid permission errors. The output included this path:

```text
/opt/lab/data/.cache/.old/.tmp/.flag1
```

[![Searching for flag files](flag1/Screenshot%202026-11-15%20140047.png)](flag1/Screenshot%202026-11-15%20140047.png)

*Searching the filesystem for names that contain `flag`.*

The path has four dot-prefixed components: `.cache`, `.old`, `.tmp`, and `.flag1`. A plain `ls` in `/opt/lab/data` would not show `.cache`, but `find` still enters it because it walks the directory tree directly.

[![Hidden path and flag](flag1/Screenshot%202026-11-15%20140105.png)](flag1/Screenshot%202026-11-15%20140105.png)

*The hidden path at the top and the flag value after `cat`.*

### Reading the file

```bash
cat /opt/lab/data/.cache/.old/.tmp/.flag1
```

```text
FLAG{hidden_files_are_not_access_control}
```

> **Flag 1:** `FLAG{hidden_files_are_not_access_control}`

### Why the hidden name did not protect it

Linux treats a leading dot as a display convention. `ls` hides such names unless `-a` is used, but the file is still a normal inode with an owner, a group, and mode bits. `find`, `cat`, and the kernel do not skip it. Access depends on the permission check, not on the name.

The successful `cat` proves the student had read permission on the file. The capture does not show the mode or owner, so the report does not claim a specific value such as `644` or `600`. If the file was readable by other users, every local account could read it. If it was readable only by its owner or group, the exposure was narrower. The available evidence cannot decide between those cases.

The directory path also matters. A user needs execute permission on each directory to reach the file. The fact that the student reached it shows the search path was open, but the exact directory modes were not recorded either.

### Impact and remediation

A secret stored in a hidden path is exposed to anyone who can read the file or search the directory, and to any process that enumerates the filesystem. Hidden names make the file harder to find, but they do not change who can read it.

The fix is to protect the file with permissions and placement. Keep secrets out of the image, store them in a secret manager or a root-only file with mode `600`, restrict the surrounding directories, and monitor access. A dot name or an unusual path should not be treated as a control.

## Flag 2: The confused deputy

This flag requires the SUID program, the exact command, the output, and the missing authorization check.

### Locating the SUID helper

The home directory contained `read-vault-fixed.c` and `maintenance.sh`, so `/opt/lab` was the next place to look. A short directory walk reached `/opt/lab/bin`. The listing there showed:

```text
-rwsr-xr-x 1 root root 16408 Oct 18 09:56 read-vault
```

The `s` in the owner execute position is the SUID bit. The file is owned by root. When `student` runs it, the process keeps real UID 1001 but gets effective UID 0.

[![Directory walk and sudo policy](flag2/Screenshot%202026-11-15%20140254.png)](flag2/Screenshot%202026-11-15%20140254.png)

*Directory walk to `/opt/lab/bin` and the sudo policy collected at the same time.*

The same listing also shows `read-vault-fixed`, which matches the output path used by the bonus grader. It is not part of the five-flag path.

[![SUID permissions](flag2/Screenshot%202026-11-15%20140604.png)](flag2/Screenshot%202026-11-15%20140604.png)

*`read-vault` carries the SUID bit and is owned by root.*

### Reading the protected file

The program expects a path argument. Running it as `student`:

```bash
./read-vault /root/flag2.txt
```

```text
[vault-reader] privileged read of: /root/flag2.txt
FLAG{confused_deputy_reads_for_the_attacker}
```

[![Flag 2 through the SUID helper](flag2/Screenshot%202026-11-15%20141039.png)](flag2/Screenshot%202026-11-15%20141039.png)

*Reading `/root/flag2.txt` through the SUID helper.*

`/root` is normally readable only by root. The student could not read the file directly, but the SUID helper could, and it did so for a path the caller chose.

> **Flag 2:** `FLAG{confused_deputy_reads_for_the_attacker}`

### The missing check

`read-vault` takes `argv[1]` and opens it. It never asks whether the caller is allowed to read that path, whether the path belongs to the caller, or whether the path is inside an allowed directory. The program has root authority, but it acts on a name supplied by an unprivileged user. That is the confused deputy pattern: a privileged program is tricked into using its authority for someone else.

The process has two identities. The real UID is the student; the effective UID is root. The kernel checks file access against the effective UID, so the open succeeds for `/root/flag2.txt`.

The security principle that fails here is complete mediation. Every access should be checked against the caller's authority, not only against the authority of the helper.

### Impact and remediation

The impact is arbitrary file read as root. The same primitive could read `/etc/shadow`, SSH keys, other users' journals, or any file under `/root`. The flag is one example.

To fix it, remove SUID and use a service with a fixed policy. If the helper must stay SUID, derive the target from the caller's real UID with `getuid` and `getpwuid`, ignore or validate `argv[1]`, use `realpath` plus a prefix check, open with `O_NOFOLLOW`, verify the file owner and type, and drop privileges after the open. The bonus appendix examines an attempted fix.

## Flag 3: Sudo and least privilege

The evidence for this flag is the relevant sudo rule, the script chain, the commands used, and the output that proves the access.

The `sudo -l` capture in the previous section lists the policy. The relevant entry for this chain is:

```text
(root) NOPASSWD: /opt/lab/bin/root-maintenance-loop.sh
```

The policy also allows `/usr/local/bin/backup-report` and `/usr/local/bin/vault-grade`. It sets `secure_path` and enables `use_pty`. The loop rule is the one used here.

> **Note on the handout order:** The handout introduces Flag 3 with the `backup-report` script and PATH resolution, and Flag 4 with a root-executed writable script. In the captured session, the two sudo chains appear in the opposite folders: the `flag3` folder records the maintenance loop, and the `flag4` folder records the backup script. The flag values are the ones stored in `/root/flag3.txt` and `/root/flag4.txt`. Both mechanisms are described below, and the final table follows the values actually recovered.

The next section shows the other sudo-authorized chain. `backup-report` resolves `tar` from the caller's directory, which is the PATH-resolution variant described in the handout. The failure class is the same: sudo trusts a script that calls an external command the caller can influence.

### The writable link in the chain

`ls -l` in `/opt/lab/bin` showed:

```text
-rwxrwxrwx 1 root root 20 Oct 24 16:42 maintenance.sh
-rwxr-xr-x 1 root root 77 Oct 18 09:56 root-maintenance-loop.sh
```

The maintenance script is owned by root but mode `777`. Every local user can write it. The loop is root-owned and is not writable.

[![World-writable maintenance script](flag3/Screenshot%202026-11-15%20141212.png)](flag3/Screenshot%202026-11-15%20141212.png)

*`maintenance.sh` is world-writable (`-rwxrwxrwx`).*

The loop content is short:

```bash
#!/bin/bash
while true; do
    /opt/lab/bin/maintenance.sh
    sleep 10
done
```

[![Root maintenance loop](flag3/Screenshot%202026-11-15%20141504.png)](flag3/Screenshot%202026-11-15%20141504.png)

*The root loop calls the writable maintenance script every ten seconds.*

The loop calls the writable script every ten seconds. The sudo rule allows the loop to run as root. When it does, the child script runs with root authority.

### Replacing the script

```bash
echo "/bin/bash -p" > maintenance.sh
```

The write succeeded because of the `777` mode. The new file contains a single command. The `-p` option tells bash to keep the effective UID instead of dropping it.

[![Replacing maintenance.sh](flag3/Screenshot%202026-11-15%20141707.png)](flag3/Screenshot%202026-11-15%20141707.png)

*Replacing `maintenance.sh` with `/bin/bash -p`.*

Starting the loop produced a shell with effective UID 0:

```text
./root-maintenance-loop.sh
id
uid=1001(student) gid=1001(student) euid=0(root) groups=1001(student)
cat /root/flag3.txt
FLAG{least_privilege_is_not_optional}
```

[![Root shell from the loop](flag3/Screenshot%202026-11-15%20141723.png)](flag3/Screenshot%202026-11-15%20141723.png)

*The loop returns a shell with effective UID 0.*

[![Reading flag 3](flag3/Screenshot%202026-11-15%20141803.png)](flag3/Screenshot%202026-11-15%20141803.png)

*Reading the third flag from the privileged shell.*

> **Flag 3:** `FLAG{least_privilege_is_not_optional}`

> **Evidence note:** The capture shows `./root-maintenance-loop.sh` without a visible `sudo` prefix, and `id` reports real UID 1001 with effective UID 0. The sudo policy above is the only rule in the capture that authorizes this script to run as root. The exact command line that produced the shell is not in the evidence, so the transition is recorded as observed rather than reconstructed.

### Why the control failed

sudo authorizes a path, and that path is a shell script. The authorization covers the script and everything the script executes. The script executes a file that any user can modify. The root-owned loop gives a false sense of safety because the dangerous file is one level down.

Least privilege would run maintenance as a service account, not root. It would also make the script read-only to everyone except its owner. The `NOPASSWD` rule removes the password barrier and makes the chain easy to repeat.

The impact is root command execution. An attacker can read every file, add users, change the sudo policy, or leave a backdoor. The flag is one visible result.

### Remediation

Set `maintenance.sh` to mode `755` or `700` and keep it owned by root. Run the loop as a dedicated user instead of root. Do not give sudo root on scripts that call mutable files. Replace the script with a compiled wrapper that takes fixed arguments, verify the script's integrity with a hash or a read-only mount, and remove `NOPASSWD` for broad scripts. Log and alert on sudo use.

## Flag 4: Root executes what you can modify

The evidence for this flag is the file executed by root, its owner, group, and permissions, the commands used, and the exact flag with the escalation chain.

This section covers the backup path. The maintenance path is in the previous section. Both were reached through sudo rules from the same policy, and both give root authority to code the student can change.

### The root-run backup script

The policy allows:

```text
(root) NOPASSWD: /usr/local/bin/backup-report
```

Reading the script shows the vulnerable call:

```bash
#!/bin/bash
# INTENTIONALLY VULNERABLE LAB PROGRAM.
# The privileged script trusts a command name resolved through PATH.
echo "[backup] generating report..."
./tar -cf /opt/lab/backups/student-backup.tar /opt/lab/data/* >/dev/null 2>&1
echo "[backup] report complete"
```

[![Backup script source](flag4/Screenshot%202026-11-15%20141904.png)](flag4/Screenshot%202026-11-15%20141904.png)

*The sudo policy and the source of `backup-report`.*

The comment says the script trusts a command name resolved through `PATH`. The captured line starts with `./tar`, so it runs the `tar` file in the current working directory. The comment and the code do not match exactly, but the security result is the same: root runs a command from a directory the student controls.

An absolute path such as `/usr/bin/tar` would remove the issue, and so would a fixed working directory owned by root. The `secure_path` setting in sudoers does not help when the script uses an explicit relative path.

### The payload

The student created `tar` in `/home/student` and wrote a command into it:

```bash
cd /home/student
touch tar
echo "chmod u+s /bin/bash" > tar
```

[![Creating the tar payload](flag4/Screenshot%202026-11-15%20142544.png)](flag4/Screenshot%202026-11-15%20142544.png)

*Creating the payload file in the student's home directory.*

The file has no shebang. When the file is executable and bash runs it, the kernel returns `ENOEXEC`, and bash falls back to reading it as a shell script. The content is one command: set the SUID bit on `/bin/bash`.

[![Running the backup and checking SUID](flag4/Screenshot%202026-11-15%20142447.png)](flag4/Screenshot%202026-11-15%20142447.png)

*Running the backup job and checking the SUID bit on `/bin/bash`.*

```text
sudo /usr/local/bin/backup-report
[backup] generating report...
[backup] report complete
ls -l /bin/bash
-rwsr-xr-x 1 root root 1446024 Mar 31  2024 /bin/bash
```

The script's own messages are the only visible output because the `tar` call redirects stdout and stderr to `/dev/null`. The `ls` line proves the payload ran: `/bin/bash` now has the SUID bit.

### Using the SUID shell

```text
/bin/bash -p
id
uid=1001(student) gid=1001(student) euid=0(root) groups=1001(student)
cat root/flag4.txt
cat: root/flag4.txt: No such file or directory
cat /root/flag4.txt
FLAG{root_should_never_execute_student_writable_code}
```

[![Reading flag 4](flag4/Screenshot%202026-11-15%20142648.png)](flag4/Screenshot%202026-11-15%20142648.png)

*Using the SUID shell to read `/root/flag4.txt`.*

The first `cat` used a relative path from the home directory and failed. The second used the absolute path and read the flag. The shell's effective UID is 0, which is why `/root/flag4.txt` is readable.

> **Flag 4:** `FLAG{root_should_never_execute_student_writable_code}`

### Owner, group, and permissions

The file executed by root in this chain is the student-created `./tar`. It was created by `student`, so its owner is `student` and that account can modify it. The capture does not show its mode. The root-owned script that invokes it is `/usr/local/bin/backup-report`; the capture does not show its owner, group, or mode either. These are the metadata items the handout asks for, and they are the main gap in the flag 4 evidence.

The payload also needed an execute bit for `./tar` to run. `touch` normally creates a file without execute permission, and the capture does not show a `chmod +x tar` command. The file may have been created earlier with the execute bit, or the command was not captured. The successful SUID change proves the file did execute, but the step that made it executable is missing from the evidence.

`/bin/bash` after the payload is `-rwsr-xr-x root root`. That value is visible in the capture.

### Why the control failed

sudo authorizes `backup-report`, but the script resolves `tar` from the caller's working directory. sudo preserves the working directory, so the student chooses which `tar` runs. The script runs as root and executes the student's file with root authority.

The failure is a trust-boundary mistake. The script treats a command name as if it were a trusted system utility, but the name is resolved in a location the caller controls. The comment in the script names `PATH` as the risk, which shows the author knew the class of bug. The implementation still leaves the resolution under student control.

The impact is root code execution and a persistent SUID shell. The payload could have copied `/etc/shadow`, added an SSH key, or changed the sudo policy instead of setting SUID on bash.

### Remediation

Use absolute paths for every external command, such as `/usr/bin/tar`. Set `PATH` to a fixed root-owned value, change to a root-owned directory before running, and keep `secure_path` in sudoers. Do not use globs that expand in attacker-controlled directories. Run the backup as a dedicated user, verify the tools with a hash or a read-only mount, and remove the SUID bit from `/bin/bash`. Audit for other SUID files after an incident.

## Flag 5: Linux capabilities

This flag requires the file that carries the capability, the capability name, the commands, the exact flag, and the reason the capability is dangerous in this context.

A filesystem-wide capability search returned one result:

```bash
getcap -r / 2>/dev/null
```

```text
/opt/lab/bin/lab-python cap_dac_read_search=ep
```

[![getcap result](flag5/Screenshot%202026-11-15%20143012.png)](flag5/Screenshot%202026-11-15%20143012.png)

*`getcap` finds the capability on `lab-python`.*

`cap_dac_read_search` allows a process to bypass discretionary access checks for reading files and searching directories. `ep` means the capability is in the effective and permitted sets, so it is active as soon as the program runs. It does not grant write access. For this lab, read access is enough.

### Using the interpreter

`lab-python` is a Python interpreter. Running it starts a normal REPL, but the process carries the capability.

```text
$ /opt/lab/bin/lab-python
Python 3.12.3 ...
>>> import os
>>> os.listdir("/")
[...]
>>> os.listdir("/root")
['.bashrc', '.profile', '.bash_history', 'flag4.txt', 'flag3.txt', 'flag5.txt', 'flag2.txt']
>>> with open('/root/flag5.txt','r') as flag5: flag5.readlines()
['FLAG{capabilities_can_be_more_precise_than_suid}\n']
```

[![Full flag 5 session](flag5/photo_2026-11-08_10-01-47.png)](flag5/photo_2026-11-08_10-01-47.png)

*Full session: `lab-python` lists `/root` and reads the fifth flag.*

The `/root` listing contains flags 2 to 5. It does not contain `flag1`, which is in the hidden path under `/opt/lab/data`. That matches the path found in Flag 1.

An earlier multi-line attempt in the same session raised `IndentationError`; the one-line `with` statement worked. This is a normal REPL mistake, not a separate finding.

The cleaned-up commands are in `flag5/lab-python.py`:

```python
import os
os.listdir("/")
os.listdir("/root")
with open('/root/flag5.txt','r') as flag5:
    flag5.readlines()
```

As a script this produces no output because `readlines()` is not printed. In the interactive session, the REPL displayed the returned list, which contained the flag. The file `flag5/flag5.txt` holds the same value:

```text
FLAG{capabilities_can_be_more_precise_than_suid}
```

> **Flag 5:** `FLAG{capabilities_can_be_more_precise_than_suid}`

### Why the capability is dangerous

A capability gives a program a specific privilege without making it SUID root. That can be safer than SUID when the program is small and does one job. Here the capability is attached to a general-purpose interpreter. Anyone who can run `lab-python` can run arbitrary Python code with the capability, so the effective privilege is arbitrary read access to every file on the system.

The capability is easy to miss because `ls -l` does not show it. `getcap` is needed. That is why the handout points to a filesystem-wide capability search.

The impact is read access to `/root`, `/etc/shadow`, private keys, and every lab flag. The interpreter also makes the attack flexible: no custom exploit is needed.

### Remediation

Remove the capability with `setcap -r /opt/lab/bin/lab-python`. Do not assign file capabilities to interpreters, shells, or other programs that accept arbitrary code. Use a small helper that opens one fixed file, drops the capability after the open, and validates the caller. Add an AppArmor or SELinux profile, and audit capabilities with `getcap -r /`.

---

## Final check: connect the five flags

The table follows the handout's final check. It uses the values and mechanisms recorded in the captures.

| Flag | Vulnerability | Mechanism | Privilege gained | Protected resource |
|---|---|---|---|---|
| Flag 1 | Hidden filename treated as protection | `find` traverses dot directories; the file was readable by `student` | None (same user) | `/opt/lab/data/.cache/.old/.tmp/.flag1` |
| Flag 2 | Confused deputy in a SUID helper | `read-vault` opens a caller-supplied path as effective root | Root file read (effective UID 0) | `/root/flag2.txt` |
| Flag 3 | Excessive sudo grant and an unsafe execution chain | The sudo loop runs world-writable `maintenance.sh`, replaced with `/bin/bash -p` | Root shell (effective UID 0) | `/root/flag3.txt` |
| Flag 4 | Root executes attacker-controlled code | `backup-report` runs `./tar` from the student's directory; the payload sets SUID on bash | Root shell through SUID bash (effective UID 0) | `/root/flag4.txt` |
| Flag 5 | Dangerous capability on a general-purpose interpreter | `cap_dac_read_search=ep` on `lab-python` bypasses read checks | Read access to root-only files | `/root/flag5.txt` |

Two notes on the table. The flag 3 and flag 4 rows follow the files read in the captures: `/root/flag3.txt` contains the least-privilege flag and `/root/flag4.txt` contains the writable-code flag. The handout introduces those two topics with the backup and maintenance scripts in the opposite order, so both chains are described and the table names the one used for each flag. The privilege for flag 5 is a read capability, not a full root shell; it is enough to read the protected file.

### Security principles

Flag 1 fails because the lab relied on a naming convention instead of a permission check. Flag 2 fails complete mediation: the helper never checks the caller's right to the requested file. Flags 3 and 4 give root authority to a chain that includes a file or command the student can change; least privilege and integrity of the execution path are both missing. Flag 5 shows that a capability is only as narrow as the program that holds it; on an interpreter, it becomes broad read access.

### Reasoning pattern

The same sequence appears in the five cases, with one variation. Reconnaissance found a hidden path, a SUID bit, a sudo rule, a writable script, or a capability. A misconfiguration turned that into access or extra authority. In Flag 1 the file was readable once found, so no extra privilege was needed. In the other four, the misconfiguration raised the process's authority. The authority reached a root-only resource, and the flag proved the access. The fix in each case is to remove the extra authority or to enforce the permission check that should have stopped it.

## Student evidence checklist

- [x] I recorded the exact flag value for each challenge. All five values are in the overview and in the flag sections.
- [x] I recorded the discovery path and commands. Each section lists them. Some command lines are partial, as noted in the gaps table.
- [x] I preserved the important command output as text. The key outputs are transcribed in the code blocks, and the original screenshots remain in the flag folders. Raw output files were not kept.
- [x] I can explain why the access-control mechanism failed. Each flag section explains why the control failed.
- [x] I can identify the security principle violated by each vulnerability. The final check covers the principles.
- [x] I can propose a remediation for each weakness. Each section ends with remediation steps.

The main evidence gaps are the exact permission metadata for Flag 1 and Flag 4, plus a few missing command lines. They are listed below.

---

## Appendix: the confused-deputy fix (bonus)

This appendix is not one of the five flags. It records the optional fix task found in the project.

### What the grader expects

The file `flag2/read-vault-content.txt` is the `vault-grade` script, despite its name. It compiles `/home/student/read-vault-fixed.c` to `/opt/lab/bin/read-vault-fixed`, sets the owner to root, and sets mode `4755`:

```bash
gcc -O2 -Wall -o "$BIN" "$SRC"
chown root:root "$BIN"
chmod 4755 "$BIN"
```

It then runs three tests as `student` through `sudo -u student`:

| Test | Command | Pass condition |
|---|---|---|
| Own journal | `/opt/lab/bin/read-vault-fixed /var/log/user-journals/student.log` | Output contains `JOURNAL: student` |
| Root flag | `/opt/lab/bin/read-vault-fixed /root/flag2.txt` | Output does not contain `FLAG{` |
| Other journal | `/opt/lab/bin/read-vault-fixed /var/log/user-journals/analyst.log` | Output does not contain `ANALYST-JOURNAL` |

If all three pass, the script prints `BONUS{deputy_checks_who_is_asking}`. That string is in the grader source. It is not proof that the student earned it.

### The attempted fix

The source in `bonus flag/fixed read-vault.txt` is close to the vulnerable program. The relevant lines are:

```c
uid = getuid(void);

if (uid == 0) {
    fp = fopen(argv[1], "r");
}

fp = fopen(argv[1], "r");
```

The attempt does not work.

- `uid` is not declared. A declaration such as `uid_t uid` is missing.
- `getuid` takes no arguments, so `getuid(void)` is not a valid call. The compiler will reject it.
- The `if` block opens the file but does not return or exit. The unconditional `fopen(argv[1], "r")` runs next, so the check has no effect.
- There is no `getpwuid` call and no path built from the caller's identity. The program still trusts `argv[1]`.
- The source would fail the grader at the compile step, before any test runs.

The note in `bonus flag/the fix.txt` says the fix is to check who is really using the file before opening it. That is the right idea, but the code does not implement it.

### What a working fix would do

A correct version would:

1. Get the real UID with `getuid()`.
2. Look up the account with `getpwuid()`.
3. Build the allowed path `/var/log/user-journals/<username>.log`.
4. Compare it with the requested path using `realpath`, or ignore the argument and open the derived path.
5. Refuse any other path, use `O_NOFOLLOW`, check that the target is a regular file owned by the expected user, drop privileges after the open, then read from the open descriptor and close it.
6. Keep the SUID binary as small as possible, or remove SUID and use group permissions.

Because the program is SUID root, the real UID is the student and the effective UID is root. `getuid()` returns the student, which is the identity the check needs. The hint in the source makes the same point.

### Status

No `vault-grade` output is saved in the project. The provided source does not compile, and the note is only a sentence. The bonus flag is therefore not verified. The value `BONUS{deputy_checks_who_is_asking}` appears in the grader script and should not be reported as earned.

## Missing information and evidence gaps

| Item | Status |
|---|---|
| Flag 1: mode and owner of `.flag1` | Not captured. The successful `cat` proves readability, not the exact bits. |
| Flag 1: full `find` output | The first capture is cropped. The matching path is visible at the top of the second capture. |
| Flag 2: SUID search command | Not captured. The SUID bit was found from `ls -l` in `/opt/lab/bin`. |
| Flag 2: no-argument usage message | Not captured. The bonus source has a usage string, but the original program's output is absent. |
| Flag 3: exact sudo invocation | The capture shows `./root-maintenance-loop.sh`, not a full `sudo` line. The sudo rule is present in `sudo -l`. |
| Flag 3: mode after overwriting `maintenance.sh` | The `777` mode is shown before the write. The write succeeded, but the mode after the write is not shown; the write does not change it. |
| Flag 4: `backup-report` metadata | Owner, group, and mode not captured. |
| Flag 4: payload `tar` mode | Created by `student`; the exact mode and the command that set the execute bit are not captured. |
| Flag 4: `tar` output | Suppressed by `>/dev/null 2>&1`; only the script's echo lines are visible. |
| Flag 5: provenance | The full session photo is dated 8 November and shows host `149251b24704`; the `getcap` capture is from 15 November. The flag value matches, but the two captures are from different sessions. |
| Bonus: grader result | No output captured. The attempted source does not compile. |

None of these gaps changes the flag values. They limit how much of the permission metadata can be stated.

The five flags show five ways to bypass access control without a kernel exploit. The common thread is that each control must be enforced by the system, not by naming or by trusting the caller.

