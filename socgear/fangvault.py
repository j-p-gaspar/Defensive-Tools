import os
import re
import json
import codecs
import base64
import html
from urllib.parse import unquote, unquote_plus, urlparse, parse_qs
import ipaddress
import sys

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
    defanged_url = re.sub(r"^(https?|ftp)", lambda m: m.group(1).replace("http", "hxxp"), val, flags=re.I)
    defanged_url = defanged_url.replace("://", "[://]").replace(".", "[.]")
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
        if not (val.strip() and set(val.strip()) <= {"="}):
            return "EncodedCommand", val

    m = re.match(r"^([a-zA-Z0-9_\-\.]+)=(.+)$", s)
    if m:
        val = m.group(2)
        if val.strip() and set(val.strip()) <= {"="}:
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
        return len(decoded_bytes) >= 3 and _mostly_printable(decoded_bytes)
    except Exception:
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
                "note": "IDN/Punycode hostname detected - possible homograph attack",
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



# ── Structured analysis ───────────────────────────────────────────────────────

def scan_webshell(raw_url: str) -> list[tuple[str, str]]:
    """Webshell / RCE rule hits across the raw URL and every decoded layer."""
    url_to_check, _ = fang(raw_url)
    findings = list(check_webshell(url_to_check))
    for comp_name, comp_data in decode_url_full(url_to_check).items():
        if comp_name in ("__idn_warning__", "__network_warning__"):
            continue
        entries = comp_data.values() if comp_name == "query_params" else [comp_data]
        for info in entries:
            if not isinstance(info, dict) or "decoded" not in info:
                continue
            candidates = [info["decoded"]] + [l["output"] for l in info.get("layers", []) if "output" in l]
            for val in candidates:
                findings.extend(check_webshell(val))
                findings.extend(check_webshell(f"={val}"))
    unique, seen = [], set()
    for rule, label in findings:
        if rule not in seen:
            unique.append((rule, label))
            seen.add(rule)
    return unique


def analyze_indicator(raw: str) -> dict:
    """Decode one indicator into a plain dict (used by every output format)."""
    url, _ = fang(raw)
    parsed = urlparse(url)
    is_full = bool(parsed.scheme in ("http", "https", "ftp") and parsed.netloc)
    res = {"input": raw, "type": "url" if is_full else "string",
           "findings": [], "components": [], "plain": True}

    def add_component(name, info):
        if info.get("encoding", "plain") == "plain":
            return
        res["plain"] = False
        res["components"].append({
            "name": name, "encoding": info["encoding"],
            "original": info["original"], "decoded": info["decoded"],
            "chain": [{"encoding": l["encoding"], "output": l.get("output", f"error: {l.get('error')}")}
                      for l in info.get("layers", [])],
        })

    if is_full:
        comps = decode_url_full(url)
        idn = comps.pop("__idn_warning__", None)
        if idn:
            res["findings"].append(
                f"[WARN] IDN/Punycode host {idn['original']} -> {idn['decoded']} (possible homograph attack)")
        for tag in comps.pop("__network_warning__", []):
            res["findings"].append(f"[INFO] Network context: {tag}")
        has_params = "query_params" in comps
        for name, info in comps.items():
            if name == "query" and has_params:
                continue          # parameters are reported individually
            if name == "query_params":
                for pname, pinfo in info.items():
                    add_component(pname, pinfo)
                continue
            for flag in info.get("traversal_flags", []):
                res["plain"] = False
                res["findings"].append(f"[WARN] Path traversal / IOC pattern: {flag}")
            intent = info.get("file_intent")
            if intent:
                sev = "HIGH" if "DANGEROUS" in intent else "INFO"
                res["findings"].append(f"[{sev}] File intent: {intent}")
            add_component(name, info)
    else:
        decoded, label, layers = detect_and_decode(url)
        if label != "plain":
            add_component("value", {"encoding": label, "original": url, "decoded": decoded,
                                    "layers": layers})
    return res


def _block(label: str, value: str, width: int = 9) -> list[str]:
    value = str(value)
    if "\n" not in value:
        return [f"{label.ljust(width)}: {value}"]
    return [f"{label.ljust(width)}:"] + [("  " + ln).rstrip() for ln in value.splitlines()]


def render_analysis(a: dict) -> str:
    out = [*_block("Input", a["input"]), f"Type     : {a['type'].upper()}"]
    out.append("Status   : " + ("PLAIN - no encoding detected" if a["plain"]
                               else f"ENCODED - {len(a['components'])} component(s)"))
    for f in a["findings"]:
        out.append(f"  {f}")
    for c in a["components"]:
        out += ["", f"[{c['name']}]"]
        out += _block("Encoding", c["encoding"])
        out += _block("Original", c["original"])
        out += _block("Decoded", c["decoded"])
        if len(c["chain"]) > 1:
            out.append("Chain    :")
            out += [f"  {i}. [{l['encoding']}] -> {l['output']}" for i, l in enumerate(c["chain"], 1)]
    return "\n".join(out)


# ── Report builders ───────────────────────────────────────────────────────────

try:                                      # package import (python -m socgear.fangvault)
    from . import common                  # noqa: E402
    from .report import Report            # noqa: E402
except ImportError:                       # loaded as a standalone file
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import common                         # noqa: E402
    from report import Report             # noqa: E402


def _indicators(text: str) -> list[str]:
    seen, out = set(), []
    for line in text.splitlines():
        v = line.strip()
        if v and not v.startswith("#") and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def defang_rows(items):
    rows = []
    for val in items:
        if is_already_defanged(val):
            ok, issues = verify_defang(val)
            if ok:
                _, cat = fang(val)
                rows.append((cat, val, "already defanged"))
                continue
            live, _ = fang(val)
            fixed, cat = defang(live)
            rows.append((cat, fixed, "corrected: " + "; ".join(i.split(" — ")[0] for i in issues)))
            continue
        d, cat = defang(val)
        rows.append((cat, d, ""))
    return rows


def run_defang(items, rep):
    rows = defang_rows(items)
    rep.table("Defanged indicators", ["Type", "Indicator", "Note"], rows)
    rep.summary = f"{len(rows)} indicators defanged"
    return len(rows)


def run_fang(items, rep):
    rows = [(cat, live) for live, cat in (fang(v) for v in items)]
    rep.table("Refanged indicators (LIVE - handle with care)", ["Type", "Indicator"], rows)
    rep.summary = f"{len(rows)} indicators refanged - do not open in a browser"
    return len(rows)


def run_decode(items, rep):
    results = [analyze_indicator(i) for i in items]
    for n, a in enumerate(results, 1):
        rep.text(f"Indicator {n}", render_analysis(a))
    hits = sum(1 for a in results if not a["plain"])
    rep.data = results
    rep.summary = f"{len(results)} analysed, {hits} encoded or flagged"
    return hits


def run_shell(items, rep):
    rows, hit_inputs = [], 0
    for raw in items:
        found = scan_webshell(raw)
        if found:
            hit_inputs += 1
            rows += [(raw, rule, label) for rule, label in found]
    rep.table("Webshell / RCE pattern matches", ["Indicator", "Pattern", "Category"], rows,
              empty="No high-risk command patterns detected")
    rep.summary = f"{len(items)} scanned, {hit_inputs} with patterns"
    return hit_inputs


def run_label(items, rep):
    rows = []
    for ip in items:
        tags = get_ip_metadata(ip)
        rows.append((ip, tags[0] if tags else "not a valid IP address"))
    rep.table("IP network context", ["IP", "Classification"], rows)
    rep.summary = f"{len(rows)} IPs classified"
    return len(rows)


def run_triage(items, rep):
    run_defang(items, rep)
    parts = []
    for fn, subset in ((run_decode, items), (run_shell, items)):
        sub = Report("", "")
        parts.append(fn(subset, sub))
        rep.sections += sub.sections
        if fn is run_decode:
            rep.data = sub.data
    ips = [i for i in items if get_ip_metadata(i)]
    if ips:
        sub = Report("", "")
        run_label(ips, sub)
        rep.sections += sub.sections
    rep.summary = (f"{len(items)} indicators; {parts[0]} encoded/flagged; "
                   f"{parts[1]} with webshell patterns")
    return sum(parts)


_COMMANDS = {"defang": run_defang, "fang": run_fang, "decode": run_decode,
             "shell": run_shell, "label": run_label, "triage": run_triage}
_TITLES = {"defang": "Defang", "fang": "Refang", "decode": "Decode", "shell": "Webshell scan",
           "label": "IP context", "triage": "Triage"}


def build_parser():
    p = common.base_parser(
        "fangvault",
        "Defang / refang IOCs, decode layered obfuscation, scan for webshell/RCE patterns.",
        epilog="examples:\n  fangvault defang http://evil.com/a.exe 8.8.8.8\n"
               "  fangvault decode 'http://x.io/?q=aGVsbG8='\n"
               "  fangvault triage -f iocs.txt --format md -o triage.md\n"
               "  cat iocs.txt | fangvault defang\n  fangvault -i",
    )
    sub = p.add_subparsers(dest="command", metavar="COMMAND")
    helps = {"defang": "make indicators safe to share", "fang": "restore live indicators",
             "decode": "decode layered encodings in a URL/string",
             "shell": "scan for webshell / RCE command patterns",
             "label": "classify IPs (public/private/...)",
             "triage": "defang + decode + shell + label in one report"}
    for name, h in helps.items():
        sp = sub.add_parser(name, help=h, formatter_class=p.formatter_class)
        common.add_input_args(sp, "items", "indicators, one per argument (or -f / stdin)")
        common.add_output_args(sp)
    p.add_argument("-i", "--interactive", action="store_true", help="interactive prompt")
    return p


def print_inline_decode(raw_url):
    """Print a plain-text decode report for one indicator."""
    print(render_analysis(analyze_indicator(raw_url)))


def _interactive():
    print("FangVault interactive. Paste an indicator to defang it.")
    print("Commands: fang | decode [x] | shell [x] | label | undo | clear | exit")
    hist = []
    while True:
        try:
            line = input("fangvault> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return common.EXIT_OK
        if not line:
            continue
        cmd, _, rest = line.partition(" ")
        cmd = cmd.lower()
        if cmd in ("exit", "quit"):
            return common.EXIT_OK
        if cmd == "clear":
            hist.clear()
            continue
        if cmd == "undo":
            if hist:
                hist.pop()
            continue
        if cmd in ("fang", "decode", "shell", "label"):
            targets = [rest.strip()] if rest.strip() else list(hist)
            if cmd == "label":
                targets = [t for t in targets if get_ip_metadata(t)]
            if not targets:
                print("Nothing to process.")
                continue
            rep = Report(f"FangVault - {_TITLES[cmd]}", "interactive", timestamp=False)
            _COMMANDS[cmd](targets, rep)
            sys.stdout.write(rep.render("text"))
            continue
        d = line if is_already_defanged(line) else defang(line)[0]
        if d not in hist:
            hist.append(d)
        print(d)


def main(argv=None):
    common.configure_stdio()
    argv = list(sys.argv[1:] if argv is None else argv)
    p = build_parser()
    if not argv and sys.stdin.isatty():
        return _interactive()
    if argv and argv[0] in ("-i", "--interactive"):
        return _interactive()
    if not argv or argv[0].startswith("-") and argv[0] not in ("-h", "--help"):
        argv = ["defang"] + argv          # piped stdin / bare flags default to defang
    args = p.parse_args(argv)
    if args.command is None:
        p.print_help(sys.stderr)
        return common.EXIT_ERROR
    try:
        text, source = common.read_input(args)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return common.EXIT_ERROR
    if text is None:
        return common.need_input(p)
    items = _indicators(text)
    if not items:
        print("error: no indicators in input", file=sys.stderr)
        return common.EXIT_ERROR
    rep = Report(f"FangVault - {_TITLES[args.command]}", source, not args.no_timestamp)
    result = _COMMANDS[args.command](items, rep)
    common.emit(rep, args)
    if args.command in ("decode", "shell", "triage"):
        return common.EXIT_OK if result else common.EXIT_NONE
    return common.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
