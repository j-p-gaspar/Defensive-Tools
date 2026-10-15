# socgear - SOC Analyst Toolkit

Command-line utilities for common SOC investigation tasks. Standard library
only, Python 3.10+. Every tool reads arguments, files or stdin, prints a
**plain-text report that pastes cleanly into a ticket**, and returns a useful
exit code, so they work in pipelines and scripts.

| Command | Tool | Purpose |
|---|---|---|
| `fangvault` | `socgear/fangvault.py` | Defang / refang IOCs, decode layered obfuscation, webshell/RCE scan |
| `ip_parser` | `socgear/ipparser.py` | Extract unique, validated IPv4/IPv6 (handles defanged + CIDR) |
| `logonlens` | `socgear/logonlens.py` | Decode Windows event IDs, NTSTATUS, Kerberos codes, logon types |
| `iocx` | `socgear/iocx.py` | Extract IPs, URLs, domains, emails, hashes, CVEs |
| `tsconv` | `socgear/tsconv.py` | Convert epoch / FILETIME / WebKit / ISO timestamps to UTC |
| `hashfile` | `socgear/hashfile.py` | MD5 / SHA1 / SHA256 of files (offline, VT link only) |
| `emailhdr` | `socgear/emailhdr.py` | Parse email headers: hops, SPF/DKIM/DMARC, spoofing hints |
| `socgear` | `socgear/cli.py` | Umbrella: `socgear ip ...`, `socgear logon ...` |

## Install

```bash
git clone https://github.com/j-p-gaspar/Defensive-Tools.git
cd Defensive-Tools
pip install .            # installs the commands above
# or run without installing:
python -m socgear ip -f firewall.log
```

`ToolKit.sh` is an optional interactive menu (Linux/macOS/WSL/Git Bash).

## Common options

Every tool takes input as arguments, `-f FILE` (repeatable, `-` = stdin) or a
pipe, and shares these output options:

| Option | Meaning |
|---|---|
| `--format text\|md\|json\|csv` | Report format. `text` (default) is plain ASCII; `md` gives Markdown tables |
| `-o FILE` | Write the report to a file |
| `--no-color` | Never emit ANSI colour (also honours `NO_COLOR`; colour is only used on a TTY) |
| `--no-timestamp` | Omit the generated time for reproducible output |
| `-q` | (`ip_parser`, `iocx`, `hashfile`) bare values only, one per line |

Results go to **stdout**; warnings and errors go to **stderr**, so
`tool > report.txt` always captures a clean report.

**Exit codes:** `0` results found, `1` nothing found, `2` error / bad input.

## Examples

```bash
# IPs from a firewall log, public only, numerically sorted
ip_parser -f fw.log --public-only --sort

# Pipe straight into other tools
cat alerts.txt | ip_parser -q | sort -u

# Decode a failed-logon dump and write a ticket-ready report
logonlens -f security.txt --threshold 10 --format md -o 4625-report.md
logonlens 4625 0xC000006A "Logon Type: 3"
logonlens --search lockout

# Defang for sharing, decode, and scan in one report
fangvault triage -f iocs.txt --format md -o triage.md
fangvault decode "http://x.io/?q=aGVsbG8gd29ybGQ="
fangvault defang http://evil.com/a.exe 8.8.8.8

# IOCs from a report, defanged
iocx -f threat-report.txt --defang

# Timestamps
tsconv 133500000000000000 1700000000 "2024-03-01 10:00:00"

# Files and email
hashfile suspicious.exe
emailhdr -f suspicious.eml
```

### Sample report (`logonlens`)

```
LogonLens - Windows authentication analysis
Source   : arguments
------------------------------------------------------------------------
Events (2)
  Event ID  Description                     Severity    Count
  --------  ------------------------------  ----------  -----
  1102      Security audit log was cleared  [CRITICAL]  1
  4625      Failed logon                    [WARN]      1

Status / error codes (1)
  Code        Table     Field  Meaning                                              Count
  ----------  --------  -----  ---------------------------------------------------  -----
  0xC000006A  NTSTATUS  -      STATUS_WRONG_PASSWORD - Known user, wrong password.  1
------------------------------------------------------------------------
Summary: 2 event hits (2 unique), 1 status codes, 1 high/critical
```

## Tool notes

**fangvault** - subcommands `defang`, `fang`, `decode`, `shell`, `label`,
`triage`; `fangvault -i` opens a plain interactive prompt. Decodes Base64/32/16,
Base64url, ROT13, JWT, URL, HTML entities, Unicode escapes and chains of them,
flags IDN/homograph hosts, path traversal, null bytes, dangerous file types and
webshell/RCE command patterns. Only the URL scheme is rewritten when defanging
(`/http-check` in a path is left alone).

**ip_parser** - validates octets (`999.1.1.1` is rejected), accepts defanged
input (`1[.]2[.]3[.]4`), IPv6 and CIDR, classifies each address
(public/private/loopback/link-local/multicast/reserved) and counts
occurrences. Filters: `--public-only`, `--only-private`, `--no-ipv6`.

**logonlens** - matches IDs and codes in context (`EventID`, `Status`,
`SubStatus`, `Failure Code`, `Logon Type`) so words, years and ports are not
mistaken for codes. Summarises top source addresses and accounts, and raises
findings for audit-log clearing and failed-logon bursts (`--threshold`).
Reads UTF-8 and UTF-16 exports. The reference data lives in
`socgear/data/logonlens.json` and is easy to extend.

**iocx** - refangs `hxxp`, `[.]`, `[@]`, `(dot)` before extracting; file names
such as `payload.exe` are not reported as domains.

## Tests

```bash
pip install pytest
pytest -q
```

## Safety

`fangvault fang` produces **live** indicators. Do not open refanged URLs in a
browser. No tool makes network requests; `hashfile` only prints a VirusTotal
link.

## Author

João Gaspar
