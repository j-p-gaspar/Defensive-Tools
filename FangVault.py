import os
import re
import json
import codecs
import base64
import html
from urllib.parse import unquote, unquote_plus, urlparse, parse_qs
import ipaddress

# --- ANSI Styling ---
BLUE    = "\033[94m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
BOLD    = "\033[1m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"
DIM     = "\033[2m"
RESET   = "\033[0m"
CLEAR   = "\033[H\033[J"

# --- Shell Rules ---

_SHELL_RULES = [
    ("=whoami", "Identity Discovery"), ("=net user", "User Management"), ("=net+user", "User Management"),
    ("=net%20user", "User Management"), ("=net%2Buser", "User Management"), ("=cmd /c", "Command Execution"),
    ("=cmd+/c+", "Command Execution"), ("=cmd%20/c", "Command Execution"), ("=cmd%2B/c", "Command Execution"),
    ("=cmd /r", "Command Execution"), ("=cmd+/r+", "Command Execution"), ("=cmd%20/r", "Command Execution"),
    ("=cmd%2B/r", "Command Execution"), ("=cmd /k", "Command Execution"), ("=cmd+/k+", "Command Execution"),
    ("=cmd%20/k", "Command Execution"), ("=cmd%2B/k", "Command Execution"), ("=powershell", "PowerShell Scripting"),
    ("=powershell+", "PowerShell Scripting"), ("=tasklist", "Process Discovery"), ("=tasklist+", "Process Discovery"),
    ("=wmic", "WMI Management"), ("=wmic+", "WMI Management"), ("=ssh", "Remote Access"), ("=ssh+", "Remote Access"),
    ("=python", "Python Scripting"), ("=python+", "Python Scripting"), ("=python3", "Python Scripting"),
    ("=python3+", "Python Scripting"), ("=ipconfig", "Network Discovery"), ("=wget", "File Download"),
    ("=wget+", "File Download"), ("=curl", "File Download"), ("=curl+", "File Download"), ("=certutil", "Living off the Land"),
    ("=copy \\\\", "SMB Exfiltration"), ("=copy%20%5C%5C", "SMB Exfiltration"), ("=dsquery", "AD Discovery"),
    ("=dsquery+", "AD Discovery"), ("=nltest", "Domain Trust Discovery"), ("=nltest+", "Domain Trust Discovery"),
    ("cmd=read", "Webshell Interaction"), ("connect&target", "Tunneling/Proxy"), ("cmd=connect", "Tunneling/Proxy"),
    ("cmd=disconnect", "Tunneling/Proxy"), ("cmd=forward", "Tunneling/Proxy")
]

# ── Defang / Fang ───────────────────────────────────────────────────────────

def is_already_defanged(val):
    has_defanged_dot      = "[.]" in val
    has_defanged_protocol = "[://]" in val or "hxxp" in val.lower()
    has_defanged_colon    = "[:]" in val
    return has_defanged_dot or has_defanged_protocol or has_defanged_colon

def verify_defang(val):
    issues = []
    raw_dots = re.sub(r"\[\.\]", "", val)
    
    if "." in raw_dots and not re.match(r"^\d{1,3}(\[\.\]\d{1,3}){3}$", val):
        issues.append("contains undefanged '.' — should be '[.]'")
        
    if "http://" in val or "https://" in val:
        issues.append("contains undefanged '://' — should be '[://]'")
    if val.lower().startswith("http") and not val.lower().startswith("hxxp"):
        issues.append("protocol not defanged — 'http' should be 'hxxp'")
    return len(issues) == 0, issues

def defang(input_str):
    if not input_str:
        return None, None
    val = input_str.strip()
    
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", val):
        return val.replace(".", "[.]").replace(":", "[:]"), "IP"
        
    if ":" in val and "." not in val:
        return val.replace(":", "[:]"), "IP"
    defanged_url = val.replace("http", "hxxp").replace("://", "[://]").replace(".", "[.]")
    return defanged_url, "URL"

def fang(input_str):
    if not input_str:
        return None, None
    val = input_str.strip()
    
    if re.match(r"^\d{1,3}(\[\.\]\d{1,3}){3}(\[:\]\d+)?$", val):
        return val.replace("[.]", ".").replace("[:]", ":"), "IP"
        
    if re.match(r"^[0-9a-fA-F:]*\[:\][0-9a-fA-F:\[\]]*$", val) and "." not in val:
        return val.replace("[:]", ":"), "IP"
    refanged_url = val.replace("hxxp", "http").replace("[://]", "://").replace("[.]", ".")
    return refanged_url, "URL"

def get_ip_metadata(ip_str: str) -> list[str]:
    clean_ip = ip_str.replace("[.]", ".").replace("[:]", ":").split(":")[0]
    tags = []
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        
        if ip_obj.is_loopback:
            tags.append("LOOPBACK / LOCALHOST IP")
        elif ip_obj.is_reserved:
            tags.append("RESERVED IP")
        elif ip_obj.is_private:
            tags.append("PRIVATE / INTERNAL IP")
        elif ip_obj.is_multicast:
            tags.append("MULTICAST IP")
        else:
            tags.append("PUBLIC / ROUTABLE IP")
    except ValueError:
        pass 
    return tags

# ── Encoding Detection & Splitting ────────────────────────────────────────────

def _mostly_printable(b: bytes) -> bool:
    if not b:
        return False
    # Strip null bytes to account for UTF-16LE (PowerShell encoded commands)
    b_clean = b.replace(b'\x00', b'')
    if not b_clean:
        return False
    printable = sum(0x20 <= byte < 0x7F or byte in (0x09, 0x0A, 0x0D) for byte in b_clean)
    return (printable / len(b_clean)) >= 0.85

def _split_kv(s):
    s = s.strip()
    
    enc_match = re.search(
        r'(?:-encodedcommand|-enc|-e|-b64)\s+["\']?([A-Za-z0-9+/={}\-_]+)["\']?', 
        s, 
        re.IGNORECASE
    )
    if enc_match:
        val = enc_match.group(1)
        if val.strip() not in ("=", "=="):
            return "EncodedCommand", val

    m = re.match(r"^([a-zA-Z0-9_\-\.]+)=(.+)$", s)
    if m:
        val = m.group(2)
        if val.strip() in ("=", "=="):
            return None, s
        return m.group(1), val
        
    val_clean = re.sub(r"\s+", "", s)
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", val_clean) and len(val_clean) >= 4:
        return None, s
        
    return None, s

def is_base64(s):
    _, val = _split_kv(s)
    val_clean = val.replace("%3D", "=").replace("%3d", "=")
    val_nospace = re.sub(r"\s+", "", val_clean)
    
    if len(val_nospace) < 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", val_nospace):
        return False
    try:
        padded = val_nospace + "=" * (-len(val_nospace) % 4)
        decoded_bytes = base64.b64decode(padded)
        return _mostly_printable(decoded_bytes)
    except:
        return False

def is_base64url(s):
    _, val = _split_kv(s)
    val_nospace = re.sub(r"\s+", "", val)
    padded = val_nospace + "=" * (-len(val_nospace) % 4)
    if len(val_nospace) < 4 or not re.fullmatch(r"[A-Za-z0-9\-_]+={0,2}", padded):
        return False
    try:
        decoded_bytes = base64.urlsafe_b64decode(padded)
        return _mostly_printable(decoded_bytes)
    except Exception:
        return False

def is_base32(s):
    _, val = _split_kv(s)
    val_upper = val.upper()
    padded = val_upper + "=" * (-len(val_upper) % 8)
    if len(val) < 8 or not re.fullmatch(r"[A-Z2-7=]+", padded):
        return False
    try:
        decoded_bytes = base64.b32decode(padded)
        return _mostly_printable(decoded_bytes)
    except Exception:
        return False

def is_base16(s):
    _, val = _split_kv(s)
    cleaned = re.sub(r"^0x|[\s:]", "", val, flags=re.IGNORECASE)
    if len(cleaned) < 4 or len(cleaned) % 2 != 0:
        return False
    if not re.fullmatch(r"[0-9A-Fa-f]+", cleaned):
        return False
    try:
        decoded_bytes = bytes.fromhex(cleaned)
        return _mostly_printable(decoded_bytes)
    except:
        return False

def is_url_encoded(s):
    _, val = _split_kv(s)
    non_padding = re.sub(r"%3[Dd]", "", val)
    return bool(re.search(r"%[0-9A-Fa-f]{2}", non_padding))

def is_html_entity(s):
    _, val = _split_kv(s)
    return bool(re.search(r"&(#\d+|#x[0-9A-Fa-f]+|[a-zA-Z]+);", val))

def is_unicode_escape(s):
    _, val = _split_kv(s)
    return bool(re.search(r"\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8}", val))

# ── JSON & ROT13 detection ────────────────────────────────────────────────────

def is_json(s):
    _, val = _split_kv(s)
    val = val.strip()
    if not ((val.startswith("{") and val.endswith("}")) or (val.startswith("[") and val.endswith("]"))):
        return False
    try:
        obj = json.loads(val)
        if isinstance(obj, (dict, list)):
            return True
        return False
    except Exception:
        return False

def is_rot13(s):
    _, val = _split_kv(s)
    if len(val) < 6:
        return False
    decoded = codecs.decode(val, "rot_13")
    keywords = {
        "http", "cmd", "powershell", "wget", "curl", "exec", "shell",
        "invoke", "bypass", "encoded", "base64", "download", "script",
        "malware", "payload", ".exe", ".ps1", ".bat", ".vbs", ".dll",
    }
    return any(kw in decoded.lower() for kw in keywords)

def rot13_decode(s):
    return codecs.decode(s, "rot_13")

# ── JWT detection ─────────────────────────────────────────────────────────────

_JWT_RE = re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$")

def is_jwt(s):
    _, val = _split_kv(s)
    if not _JWT_RE.fullmatch(val):
        return False
    parts = val.split(".")
    return len(parts[0]) >= 10 and len(parts[1]) >= 10

def decode_jwt(s):
    parts = s.strip().split(".")
    result = {}
    for i, name in enumerate(["header", "payload"]):
        if i >= len(parts):
            break
        seg = parts[i]
        padded = seg + "=" * (-len(seg) % 4)
        try:
            raw = base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
            result[name] = json.loads(raw)
        except Exception:
            result[name] = seg
    result["signature"] = parts[2] if len(parts) > 2 else ""
    return result

# ── Punycode / IDN decoding ───────────────────────────────────────────────────

def decode_punycode(hostname: str) -> str | None:
    labels = hostname.split(".")
    if not any(l.lower().startswith("xn--") for l in labels):
        return None
    try:
        return hostname.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        decoded_labels = []
        for label in labels:
            if label.lower().startswith("xn--"):
                try:
                    decoded_labels.append((label + ".").encode("ascii").decode("idna").rstrip("."))
                except Exception:
                    decoded_labels.append(label)
            else:
                decoded_labels.append(label)
        result = ".".join(decoded_labels)
        return result if result != hostname else None

# ── Path traversal / IOC flag detection ───────────────────────────────────────

_TRAVERSAL_PATTERNS = [
    (r"\.\./",               "directory traversal (../)"),
    (r"%2[Ff]",              "URL-encoded slash (%2F)"),
    (r"%252[Ff]",            "double-encoded slash (%252F)"),
    (r"%00",                 "null byte (%00)"),
    (r"\.\.%[0-9A-Fa-f]{2}", "encoded traversal sequence"),
]

def check_path_traversal(path: str) -> list[str]:
    findings = []
    for pattern, label in _TRAVERSAL_PATTERNS:
        if re.search(pattern, path):
            findings.append(label)
    return findings

# ── Detection order & Run Decoder ────────────────────────────────────────────

def _detect(s):
    if is_jwt(s):            return "JWT"
    if is_json(s):           return "JSON"
    if is_html_entity(s):    return "HTML entity"
    if is_unicode_escape(s): return "Unicode escape"
    if is_base16(s):         return "Base16/Hex"
    if is_base32(s):         return "Base32"
    if is_base64(s):         return "Base64"        
    if is_base64url(s):      return "Base64url"     
    if is_url_encoded(s):    return "URL-encoded"
    if is_rot13(s):          return "ROT13"
    return "plain"

def _run_decoder(enc, s):
    key, val = _split_kv(s)
    
    try:
        if enc == "URL-encoded":
            decoded = unquote_plus(val)
        elif enc == "JSON":
            parsed_json = json.loads(val)
            decoded = json.dumps(parsed_json, indent=2)
        elif enc == "HTML entity":
            decoded = html.unescape(val)
        elif enc == "Unicode escape":
            decoded = re.sub(r"\\U([0-9A-Fa-f]{8})", lambda m: chr(int(m.group(1), 16)), val)
            decoded = re.sub(r"\\u([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), decoded)
        elif enc == "Base16/Hex":
            cleaned = re.sub(r"^0x|[\s:]", "", val, flags=re.IGNORECASE)
            decoded = bytes.fromhex(cleaned).decode("utf-8", errors="replace")
        elif enc == "Base32":
            padded = val.strip().upper() + "=" * (-len(val.strip()) % 8)
            decoded = base64.b32decode(padded).decode("utf-8", errors="replace")
        elif enc == "Base64url":
            padded = val.strip() + "=" * (-len(val.strip()) % 4)
            decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
        elif enc == "Base64":
            val_clean = val.replace("%3D", "=").replace("%3d", "=")
            val_nospace = re.sub(r"\s+", "", val_clean)
            padded = val_nospace + "=" * (-len(val_nospace) % 4)
            decoded_bytes = base64.b64decode(padded)
            
            # Handle PowerShell's UTF-16LE gracefully
            if b'\x00' in decoded_bytes:
                decoded = decoded_bytes.decode("utf-16le", errors="replace")
            else:
                decoded = decoded_bytes.decode("utf-8", errors="replace")
                
        elif enc == "ROT13":
            decoded = rot13_decode(val)
        elif enc == "JWT":
            decoded = json.dumps(decode_jwt(val), indent=2)
        else:
            decoded = val
            
        if key:
            if key == "EncodedCommand":
                return f"Powershell_Decoded_Script:\n{decoded}"
            return f"{key}={decoded}"
        return decoded
    except Exception as e:
        raise e

def detect_and_decode(s):
    layers  = []
    seen    = set()
    current = s

    while True:
        if current in seen:
            break
        seen.add(current)
        enc = _detect(current)
        if enc == "plain":
            break
        try:
            decoded = _run_decoder(enc, current)
        except Exception as e:
            layers.append({"encoding": enc, "error": str(e)})
            break
        layers.append({"encoding": enc, "input": current, "output": decoded})
        current = decoded
        
        if enc in ("JWT", "JSON") or current.startswith("Powershell_Decoded_Script:\n"):
            break

    label = " → ".join(l["encoding"] for l in layers) if layers else "plain"
    return current, label, layers

def decode_url_full(url):
    parsed = urlparse(url)
    components = {
        "scheme":   parsed.scheme,
        "netloc":   parsed.netloc,
        "path":     parsed.path,
        "query":    parsed.query,
        "fragment": parsed.fragment,
    }

    results = {}

    if parsed.netloc:
        idn_decoded = decode_punycode(parsed.netloc)
        if idn_decoded:
            results["__idn_warning__"] = {
                "original": parsed.netloc,
                "decoded":  idn_decoded,
                "note": "⚠ IDN/Punycode hostname detected — possible homograph attack",
            }
        
        netloc_no_port = parsed.netloc.split(":")[0] 
        ip_tags = get_ip_metadata(netloc_no_port)
        if ip_tags:
            results["__network_warning__"] = ip_tags

    for name, value in components.items():
        if not value:
            continue
        decoded, label, layers = detect_and_decode(value)
        entry = {
            "original": value,
            "decoded":  decoded,
            "encoding": label,
            "layers":   layers,
        }
        
        if name == "path":
            flags = check_path_traversal(value) or check_path_traversal(decoded)
            if flags:
                entry["traversal_flags"] = flags
                
            file_intent = check_file_intent(decoded)
            if file_intent:
                entry["file_intent"] = file_intent
                
        results[name] = entry

    # Replaced parse_qs with manual raw string parsing to preserve encoding state
    if parsed.query:
        params = {}
        for pair in parsed.query.split("&"):
            if not pair: continue
            if "=" in pair:
                k, v = pair.split("=", 1)
            else:
                k, v = pair, ""
            
            decoded, label, layers = detect_and_decode(v)
            k_dec = unquote_plus(k)
            
            base_key = f"param '{k_dec}'"
            unique_key = base_key
            counter = 1
            while unique_key in params:
                counter += 1
                unique_key = f"{base_key} [{counter}]"
                
            params[unique_key] = {
                "original": v,
                "decoded":  decoded,
                "encoding": label,
                "layers":   layers,
            }
        if params:
            results["query_params"] = params

    return results

def check_webshell(url: str) -> list[tuple[str, str]]:
    findings = []
    decoded_url = unquote_plus(url).lower()
    raw_url = url.lower()
    
    for rule, label in _SHELL_RULES:
        if rule.lower() in raw_url or rule.lower() in decoded_url:
            findings.append((rule, label))
    return findings

# ── TUI helpers ───────────────────────────────────────────────────────────────

def print_ui():
    print(f"{CYAN}╔══════════════════════════════════════════════════════════════════════╗")
    print(f"║ {BOLD}{MAGENTA}FANG-VAULT v6.2{RESET}{CYAN}                                                      ║")
    print(f"╠══════════════════════════════════════════════════════════════════════╣")
    print(f"║ {BOLD}COMMANDS:{RESET} {YELLOW}clear{RESET} | {YELLOW}fang{RESET} | {YELLOW}decode{RESET} | {YELLOW}label{RESET} | {YELLOW}shell{RESET} | {YELLOW}undo{RESET} | {RED}exit{RESET}        {CYAN}║")
    print(f"║ {BOLD}INLINE:{RESET}   {YELLOW}decode <url>{RESET} | {YELLOW}shell <url>{RESET}                                 {CYAN}║")
    print(f"╚══════════════════════════════════════════════════════════════════════╝{RESET}")

def print_history(history_ips, history_urls):
    if history_ips:
        print(f"{BOLD}{BLUE}─── DEFANGED IPs ───{RESET}")
        for ip in history_ips:
            print(f"{WHITE}{ip}{RESET}")
        print(f"{BLUE}────────────────────{RESET}\n")
    if history_urls:
        print(f"{BOLD}{GREEN}─── DEFANGED URLs ───{RESET}")
        for url in history_urls:
            print(f"{BOLD}{WHITE}URL:{RESET} {url}\n")
        print(f"{GREEN}─────────────────────{RESET}\n")

def _print_single_decode(raw_url):
    url_to_decode, _ = fang(raw_url)
    parsed      = urlparse(url_to_decode)
    is_full_url = parsed.scheme in ("http", "https", "ftp") and parsed.netloc

    print(f"  {DIM}{'─' * 54}{RESET}")
    print(f"  {BOLD}{WHITE}Input:{RESET} {YELLOW}{raw_url}{RESET}")

    if is_full_url:
        components = decode_url_full(url_to_decode)

        if "__idn_warning__" in components:
            idn = components.pop("__idn_warning__")
            print(f"\n  {RED}{BOLD}{idn['note']}{RESET}")
            print(f"  {DIM}{'Original':<12}{RESET} {YELLOW}{idn['original']}{RESET}")
            print(f"  {DIM}{'Unicode':<12}{RESET}  {GREEN}{idn['decoded']}{RESET}")

        if "__network_warning__" in components:
            net_tags = components.pop("__network_warning__")
            print(f"\n  {BOLD}{CYAN}Network Context:{RESET}")
            for tag in net_tags:
                color = GREEN if "PUBLIC" in tag else YELLOW
                print(f"    {color}►{RESET} {WHITE}{tag}{RESET}")

        has_encoded = any(
            info.get("encoding", "plain") != "plain"
            for k, info in components.items()
            if k != "query_params"
        )
        has_encoded_params = (
            "query_params" in components and
            any(p.get("encoding", "plain") != "plain" for p in components["query_params"].values())
        )
        has_traversal = any(
            "traversal_flags" in info
            for k, info in components.items()
            if isinstance(info, dict) and k != "query_params"
        )

        if not has_encoded and not has_encoded_params and not has_traversal:
            print(f"  {DIM}Status:{RESET} {GREEN}Plain — no encoding detected{RESET}\n")
            return

        for comp, info in components.items():
            if not isinstance(info, dict):
                continue
            if "traversal_flags" in info:
                print(f"\n  {RED}{BOLD}⚠ Path traversal / IOC patterns detected:{RESET}")
                for flag in info["traversal_flags"]:
                    print(f"    {RED}✗{RESET} {WHITE}{flag}{RESET}")
            if "file_intent" in info:
                intent = info["file_intent"]
                print(f"\n  {BOLD}{MAGENTA}File / Download Intent:{RESET}")
                if "DANGEROUS" in intent:
                    print(f"    {RED}⚠{RESET} {RED}{BOLD}{intent}{RESET}")
                else:
                    print(f"    {GREEN}ℹ{RESET} {GREEN}{intent}{RESET}")
            if comp == "query_params":
                for param, pinfo in info.items():
                    if pinfo["encoding"] != "plain":
                        print(f"\n  {BOLD}[{param}]{RESET}")
                        print(f"  {DIM}{'Encoding':<12}{RESET} {CYAN}{pinfo['encoding']}{RESET}")
                        print(f"  {DIM}{'Original':<12}{RESET} {YELLOW}{pinfo['original']}{RESET}")
                        print(f"  {DIM}{'Decoded':<12}{RESET}  {GREEN}{pinfo['decoded']}{RESET}")
                        if len(pinfo.get("layers", [])) > 1:
                            print(f"  {DIM}{'Chain':<12}{RESET}", end="")
                            for i, layer in enumerate(pinfo["layers"], 1):
                                print(f" {i}.[{layer['encoding']}] → {layer['output']}", end="")
                            print()
            else:
                if info.get("encoding", "plain") != "plain":
                    print(f"\n  {BOLD}[{comp}]{RESET}")
                    print(f"  {DIM}{'Encoding':<12}{RESET} {CYAN}{info['encoding']}{RESET}")
                    print(f"  {DIM}{'Original':<12}{RESET} {YELLOW}{info['original']}{RESET}")
                    print(f"  {DIM}{'Decoded':<12}{RESET}  {GREEN}{info['decoded']}{RESET}")
    else:
        decoded, label, layers = detect_and_decode(url_to_decode)
        if label == "plain":
            print(f"  {DIM}Status:{RESET} {GREEN}Plain — no encoding detected{RESET}")
        else:
            print(f"  {DIM}{'Encoding':<12}{RESET} {CYAN}{label}{RESET}")
            print(f"  {DIM}{'Decoded':<12}{RESET}\n{GREEN}{decoded}{RESET}")
            if len(layers) > 1:
                print(f"  {BOLD}Decoding chain:{RESET}")
                for i, layer in enumerate(layers, 1):
                    if "error" in layer:
                        print(f"    {i}. {RED}[{layer['encoding']}] error: {layer['error']}{RESET}")
                    else:
                        print(f"    {i}. {DIM}[{layer['encoding']}]{RESET} → {GREEN}{layer['output']}{RESET}")
    print()

def print_decode_results(history_urls):
    print(CLEAR, end="")
    print_ui()
    if not history_urls:
        print(f"{YELLOW}No URLs in history to decode.{RESET}\n")
        input(f"{CYAN}Press Enter to continue...{RESET}")
        print(CLEAR, end="")
        return
    print(f"{BOLD}{MAGENTA}─── DECODE RESULTS ──────────────────────────────────────{RESET}\n")
    for raw_url in history_urls:
        _print_single_decode(raw_url)
    print(f"{BOLD}{MAGENTA}─────────────────────────────────────────────────────────{RESET}\n")
    input(f"{CYAN}Press Enter to continue...{RESET}")
    print(CLEAR, end="")

def print_inline_decode(raw_url):
    print(CLEAR, end="")
    print_ui()
    print(f"{BOLD}{MAGENTA}─── INLINE DECODE ───────────────────────────────────────{RESET}\n")
    _print_single_decode(raw_url)
    print(f"{BOLD}{MAGENTA}─────────────────────────────────────────────────────────{RESET}\n")
    input(f"{CYAN}Press Enter to continue...{RESET}")
    print(CLEAR, end="")

# ── File / Download Intent Detection ──────────────────────────────────────────

_DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".msi",
    ".ps1", ".bat", ".vbs", ".vbe", ".js", ".jse",
    ".zip", ".rar", ".7z", ".iso", ".img", ".cab",
    ".sh", ".py", ".elf",
    ".docm", ".xlsm", ".pptm"
}

_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico"}

def check_file_intent(path: str) -> str | None:
    ext = os.path.splitext(path.lower())[1]
    if ext in _DANGEROUS_EXTENSIONS:
        return f"DANGEROUS FILE: {ext} (Potential Payload)"
    if ext in _IMAGE_EXTENSIONS:
        return f"IMAGE FILE: {ext}"
    return None

def print_shell_results(history_urls):
    print(CLEAR, end="")
    print_ui()
    
    print(f"{BOLD}{RED}─── WEBSHELL / RCE SCAN RESULTS ─────────────────────────{RESET}\n")
    for raw_url in history_urls:
        url_to_check, _ = fang(raw_url)
        all_findings = []
        
        all_findings.extend(check_webshell(url_to_check))
        parsed_components = decode_url_full(url_to_check)
        
        for comp_name, comp_data in parsed_components.items():
            if comp_name in ["__idn_warning__", "__network_warning__"]:
                continue
                
            if comp_name == "query_params":
                for param_key, pinfo in comp_data.items():
                    val = pinfo['decoded']
                    all_findings.extend(check_webshell(val))
                    all_findings.extend(check_webshell(f"={val}"))
                    
                    for layer in pinfo.get("layers", []):
                        if "output" in layer:
                            out = layer['output']
                            all_findings.extend(check_webshell(out))
                            all_findings.extend(check_webshell(f"={out}"))
                            
            elif isinstance(comp_data, dict) and "decoded" in comp_data:
                val = comp_data["decoded"]
                all_findings.extend(check_webshell(val))
                all_findings.extend(check_webshell(f"={val}"))
                
                for layer in comp_data.get("layers", []):
                    if "output" in layer:
                        out = layer['output']
                        all_findings.extend(check_webshell(out))
                        all_findings.extend(check_webshell(f"={out}"))

        unique_findings = []
        seen = set()
        for rule, label in all_findings:
            if rule not in seen:
                unique_findings.append((rule, label))
                seen.add(rule)

        print(f"  {BOLD}{WHITE}URL:{RESET} {YELLOW}{raw_url}{RESET}")
        if unique_findings:
            print(f"  {RED}{BOLD}⚠ WEBSHELL DETECTED:{RESET}")
            for rule, label in unique_findings:
                print(f"    {RED}✗{RESET} {WHITE}{rule:<18}{RESET} {DIM}→{RESET} {MAGENTA}{label}{RESET}")
        else:
            print(f"  {GREEN}✓ No high-risk command patterns detected.{RESET}")
        print(f"  {DIM}{'─' * 54}{RESET}")
    
    input(f"\n{CYAN}Press Enter to continue...{RESET}")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    history_ips  = []
    history_urls = []
    history_log  = []
    print(CLEAR, end="")

    while True:
        print(CLEAR, end="")
        print_ui()
        print_history(history_ips, history_urls)

        try:
            prompt     = f"{BOLD}{GREEN}soc-analyst@tools{RESET}:{CYAN}~$ {RESET}"
            user_input = input(prompt).strip()

            if not user_input:
                continue

            cmd_lower = user_input.lower()

            if cmd_lower in ["exit", "quit"]:
                print(f"{RED}Shutting down...{RESET}")
                break

            if cmd_lower == "clear":
                history_ips  = []
                history_urls = []
                history_log  = []
                continue

            if cmd_lower == "undo":
                if not history_log:
                    print(f"{YELLOW}Nothing to undo.{RESET}")
                    input(f"{CYAN}Press Enter to continue...{RESET}")
                    continue
                last_type, last_val = history_log.pop()
                if last_type == "IP":
                    history_ips.remove(last_val)
                elif last_type == "URL":
                    history_urls.remove(last_val)
                continue

            if cmd_lower == "fang":
                if not history_ips and not history_urls:
                    print(f"{YELLOW}No indicators to refang.{RESET}")
                    input(f"{CYAN}Press Enter to continue...{RESET}")
                    continue
                print(CLEAR, end="")
                print_ui()
                if history_ips:
                    print(f"{BOLD}{YELLOW}─── FANGED IPs ───{RESET}")
                    for ip in history_ips:
                        refanged_val, _ = fang(ip)
                        print(f"{RED}{refanged_val}{RESET}")
                    print(f"{YELLOW}────────────────────{RESET}\n")
                if history_urls:
                    print(f"{BOLD}{YELLOW}─── REFANGED URLs ───{RESET}")
                    for url in history_urls:
                        refanged_val, _ = fang(url)
                        print(f"{BOLD}{WHITE}URL:{RESET} {RED}{refanged_val}{RESET}\n")
                    print(f"{YELLOW}─────────────────────{RESET}\n")
                input(f"{CYAN}Press Enter to continue...{RESET}")
                continue

            if cmd_lower == "decode":
                print_decode_results(history_urls)
                continue

            if cmd_lower.startswith("decode "):
                inline_target = user_input[7:].strip()
                if inline_target:
                    print_inline_decode(inline_target)
                else:
                    print(f"{YELLOW}Usage: decode <url_or_indicator>{RESET}")
                    input(f"{CYAN}Press Enter to continue...{RESET}")
                continue

            val = user_input.strip()

            if is_already_defanged(val):
                is_valid, issues = verify_defang(val)
                _, category = fang(val)

                if is_valid:
                    if category == "IP" and val not in history_ips:
                        history_ips.append(val)
                        history_log.append(("IP", val))
                    elif category == "URL" and val not in history_urls:
                        history_urls.append(val)
                        history_log.append(("URL", val))
                else:
                    refanged_val, _ = fang(val)
                    fixed, _         = defang(refanged_val)
                    print(CLEAR, end="")
                    print_ui()
                    print_history(history_ips, history_urls)
                    print(f"{YELLOW}⚠ Defang issues found — auto-corrected and added:{RESET}\n")
                    for issue in issues:
                        print(f"  {RED}✗{RESET} {WHITE}{issue}{RESET}")
                    print(f"\n  {DIM}Input:{RESET}  {YELLOW}{val}{RESET}")
                    print(f"  {DIM}Fixed:{RESET}  {GREEN}{fixed}{RESET}\n")

                    _, fixed_category = fang(fixed)
                    if fixed_category == "IP" and fixed not in history_ips:
                        history_ips.append(fixed)
                        history_log.append(("IP", fixed))
                    elif fixed_category == "URL" and fixed not in history_urls:
                        history_urls.append(fixed)
                        history_log.append(("URL", fixed))

                    input(f"{CYAN}Press Enter to continue...{RESET}")
                continue

            if cmd_lower == "label":
                if not history_ips:
                    print(f"{YELLOW}No IPs in history to label.{RESET}\n")
                    input(f"{CYAN}Press Enter to continue...{RESET}")
                    continue
                
                print(CLEAR, end="")
                print_ui()
                print(f"{BOLD}{MAGENTA}─── IP NETWORK CONTEXT  ─────────────────────────────────{RESET}\n")
                
                for ip in history_ips:
                    tags = get_ip_metadata(ip)
                    print(f"  {BOLD}{WHITE}IP:{RESET} {YELLOW}{ip}{RESET}")
                    
                    if tags:
                        for tag in tags:
                            color = GREEN if "PUBLIC" in tag else YELLOW
                            print(f"    {color}► {BOLD}{tag}{RESET}")
                    else:
                        print(f"    {DIM}► Status: Not a valid IP address.{RESET}")
                    print()
                    
                print(f"{BOLD}{MAGENTA}─────────────────────────────────────────────────────────{RESET}\n")
                input(f"{CYAN}Press Enter to continue...{RESET}")
                continue

            if cmd_lower == "shell":
                print_shell_results(history_urls)
                continue

            if cmd_lower.startswith("shell "):
                inline_target = user_input[6:].strip()
                if inline_target:
                    print(CLEAR, end="")
                    print_ui()
                    print(f"{BOLD}{RED}─── INLINE SHELL SCAN ───────────────────────────────────{RESET}\n")
                    print_shell_results([inline_target])
                continue

            defanged_val, category = defang(val)
            if category == "IP" and defanged_val not in history_ips:
                history_ips.append(defanged_val)
                history_log.append(("IP", defanged_val))
            elif category == "URL" and defanged_val not in history_urls:
                history_urls.append(defanged_val)
                history_log.append(("URL", defanged_val))

        except KeyboardInterrupt:
            print(f"\n{RED}Exiting...{RESET}")
            break

if __name__ == "__main__":
    if os.name == "nt":
        os.system("color")
    main()