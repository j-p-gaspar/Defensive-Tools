# SOC Analyst Investigation Toolkit

A collection of lightweight Python CLI utilities built for **Security Operations Center (SOC) analysts** to accelerate common investigative tasks — IOC defanging, multi-layer decoding, IP extraction, and Windows authentication log decoding.

---

## 📁 Repository Structure

```text
SOC-Toolkit/
├── FangVault.py       # URL & IP defanger, multi-layer decoder, and payload analyzer
├── IP_Parser.py       # IPv4 extractor and deduplicator from raw text
├── LogonLens.py       # Windows Event ID & hex status code decoder
├── ToolKit.sh         # Interactive Bash menu launcher
├── Test_FangVault.py  # Unit test suite for FangVault capabilities
└── README.md
```

---

## 🛠️ Tools Overview

### 1. Cyber Defanger & Decoder — `FangVault.py`

Safely document, share, and inspect malicious indicators without risking accidental execution by analysts or end-users.

#### How It Works

- Converts `http` / `https` → `hxxp` / `hxxps`
- Wraps URL separators in brackets:
  - `hxxp[://]malicious[.]com`
- Detects and defangs IPv4 and IPv6 addresses:
  - `192[.]168[.]1[.]1`
- Validates already-defanged input and attempts to correct malformed indicators.
- Refangs defanged indicators back into their live form using the `fang` command.
- Automatically unwraps chained encodings, such as:
  - Base64 → URL encoding

#### Advanced Payload & IOC Analysis

`FangVault.py` supports analysis and decoding of several common encoding and obfuscation techniques, as well as threat-hunting scans.

**Decoding:**

- Base64
- Base32
- Base16 / Hex
- ROT13
- JWT (JSON Web Tokens)
- URL encoding
- HTML entities
- Unicode escapes

**Domain Analysis:**

- Punycode / IDN decoding
- Homograph attack warnings

**Path Traversal & Null-Byte Detection:**

- `../`
- `%2F`
- `%00`

**Webshell & RCE Scanning:**

Scans decoded URL components for high-risk command patterns, including:

- PowerShell scripting
- Command execution
- Tunneling
- WMI management

Available through the `shell` command.

**IP Network Classification:**

Evaluates IP addresses and classifies them as:

- Private
- Public
- Loopback
- Multicast
- Reserved

Available through the `label` command.

**File Intent Detection:**

Flags potentially dangerous executable file types found within download links.

#### Commands

| Command | Description |
|---|---|
| `<url or ip>` | Defang a fresh indicator and add it to session history |
| `fang` | Reverse all session indicators back to live form |
| `decode` | Decode and analyze components of all URLs in session history |
| `decode <url>` | Perform an inline full decoding and analysis of a specific URL |
| `shell` | Scan all decoded URLs in session history for Webshell and RCE patterns |
| `shell <url>` | Perform an inline Webshell / RCE pattern scan on a specific URL |
| `label` | Evaluate and display the IP network context for IPs in session history |
| `undo` | Remove the last added indicator from session history |
| `clear` | Reset all session history |
| `exit` / `quit` | Terminate the tool |

---

### 2. IP Parser — `IP_Parser.py`

Rapidly extract all unique IPv4 addresses from unstructured text such as:

- Firewall logs
- Email headers
- Threat intelligence reports
- Raw packet dumps

#### How It Works

- Uses a regular expression pattern to identify IPv4 addresses in arbitrary text.
- Automatically removes duplicate addresses using a Python `set`.
- Returns a clean list of unique IPv4 addresses.
- Displays the total number of unique addresses found.
- Supports looping input, allowing multiple data chunks to be processed in a single session.

---

### 3. LogonLens — `LogonLens.py`

Translate cryptic Windows Event IDs and hexadecimal NTSTATUS/Kerberos status codes into human-readable security context during incident investigations.

#### How It Works

Raw log data containing hexadecimal status codes or Windows Event IDs is automatically parsed and matched against a built-in reference database.

#### Coverage

| Category | Examples |
|---|---|
| Authentication Errors | `0xC0000064`, `0xC000006A`, `0xC0000234` |
| Kerberos Errors | `0x6`, `0x17`, `0x25` |
| Logon / Logoff Events | `4624`, `4625`, `4634`, `4648` |
| Account Management | `4720`, `4725`, `4740` |
| Kerberos / NTLM | `4768`, `4769`, `4771`, `4776` |
| System & Policy | `1102`, `4719`, `4732` |

#### Features

- Automatic extraction of Event IDs and status codes from raw log snippets.
- Inline database search using:
  ```text
  search [term]
  ```
- Session-scoped analysis tracking discovered events and errors.
- Differentiates between:
  - `[EVENTS]`
  - `[ERRORS]`

---

## 🚀 Getting Started

### Prerequisites

- Python 3.x
- A terminal emulator with ANSI color support:
  - Windows Terminal
  - PowerShell
  - VS Code Terminal
  - iTerm2
  - Linux terminals
  - macOS Terminal

> **Note:** Classic Windows CMD may not render ANSI colors correctly. For the best experience on Windows, use Windows Terminal or PowerShell.

---

## 📦 Installation

No external Python dependencies are required. All scripts use the Python standard library only.

```bash
git clone https://github.com/your-username/soc-analyst-toolkit.git
cd soc-analyst-toolkit
```

---

## ▶️ Usage

You can run the individual Python utilities directly or use the interactive menu launcher.

### Using the Menu Launcher

#### Linux / macOS

```bash
chmod +x ToolKit.sh
./ToolKit.sh
```

#### Windows

`ToolKit.sh` requires a Bash-compatible environment such as:

- WSL
- Git Bash
- MSYS2

Alternatively, run the Python tools directly.

---

### Running Scripts Directly

#### FangVault

Defang malicious URLs/IPs and decode payloads:

```bash
python3 FangVault.py
```

#### IP Parser

Extract unique IPv4 addresses from raw log data:

```bash
python3 IP_Parser.py
```

#### LogonLens

Decode Windows authentication failures and Event IDs:

```bash
python3 LogonLens.py
```

---

## 💻 Compatibility

| Tool | Windows | Linux | macOS |
|---|:---:|:---:|:---:|
| `FangVault.py` | ✅ | ✅ | ✅ |
| `IP_Parser.py` | ✅ | ✅ | ✅ |
| `LogonLens.py` | ✅ | ✅ | ✅ |
| `ToolKit.sh` | ⚠️ WSL / Bash | ✅ | ✅ |

---

## 🔐 Security Use Cases

This toolkit is designed to assist SOC analysts and security practitioners with common investigation tasks, including:

- IOC normalization and documentation
- Malicious URL analysis
- IP address extraction
- Encoded payload inspection
- Authentication failure investigation
- Windows Event Log analysis
- Kerberos and NTLM troubleshooting
- Threat intelligence enrichment
- Initial incident triage

> **Warning:** The `fang` functionality converts defanged indicators back into potentially active URLs or IP-based indicators. Exercise caution when handling or opening refanged content.

---

## 👤 Author

**João Gaspar**

Security-focused utilities for SOC analysis, incident response, and threat intelligence workflows.
