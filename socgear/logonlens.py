"""logonlens - decode Windows Event IDs, NTSTATUS / Kerberos codes and logon types."""
import json
import os
import re
import sys
from collections import Counter

from . import common
from .report import Report

_DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "logonlens.json")
with open(_DATA_PATH, encoding="utf-8") as _fh:
    DB = json.load(_fh)

EVENTS = DB["events"]                                   # id -> [desc, severity]
STATUS = {k.upper().replace("0X", "0x"): v for k, v in DB["status"].items()}
WIN32 = DB["win32"]
KERBEROS = DB["kerberos"]
LOGON_TYPES = DB["logon_types"]
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "WARN": 2, "INFO": 3}

# Fields that carry a hex status; Kerberos-ish labels prefer the Kerberos table.
_HEX_CTX = re.compile(
    r"(?P<label>Sub\s*Status|Status|Failure\s*Code|Result\s*Code|Error\s*Code|"
    r"Ticket\s*Status|ErrorCode|ResultCode|FailureCode)[\"'>:=\s]{1,6}(?P<val>0x[0-9A-Fa-f]{1,8})",
    re.IGNORECASE)
_HEX_BARE = re.compile(r"(?<![\w.])(?:0[xX])?([0-9A-Fa-f]{1,8})(?![\w])")
_EVT_CTX = re.compile(
    r"(?:Event\s*ID|EventID|Event\s*Code|EventCode)[\"'>:=\s]{1,6}(?P<id>\d{2,5})", re.IGNORECASE)
_EVT_BARE = re.compile(r"(?<![\w.:/\-])(\d{4,5})(?![\w]|\.\d)")
_LOGON_TYPE = re.compile(r"Logon\s*Type[\"'>:=\s]{1,6}(\d{1,2})", re.IGNORECASE)
_SRC_IP = re.compile(
    r"(?:Source Network Address|IpAddress|Client Address|Source Address|SourceAddress|"
    r"Source IP)[\"'>:=\s]{1,6}([0-9A-Fa-f:.]{3,45})", re.IGNORECASE)
_USER = re.compile(
    r"(?:Target\s*User\s*Name|TargetUserName|Account Name|User Name)[\"'>:=\s]{1,6}"
    r"([^\s<\"',;]+)", re.IGNORECASE)
_KRB_LABELS = ("failure", "result", "ticket", "error")


def _norm_hex(val):
    return "0x" + val[2:].upper().lstrip("0").rjust(1, "0") if val.lower().startswith("0x") else val


def lookup_status(code, prefer_kerberos=False):
    """Return (category, description) for a normalised 0x.. code or None."""
    tables = [("KERBEROS", KERBEROS), ("NTSTATUS", STATUS), ("WIN32", WIN32)]
    if not prefer_kerberos:
        tables = [tables[1], tables[2], tables[0]]
    for cat, table in tables:
        if code in table:
            return cat, table[code]
    # NTSTATUS keys are 8-digit; compare numerically as a fallback
    try:
        n = int(code, 16)
    except ValueError:
        return None
    for cat, table in tables:
        for k, v in table.items():
            if int(k, 16) == n:
                return cat, v
    return None


def analyze(text, strict=False):
    """Extract events, status codes and context from raw log text."""
    events, statuses, ltypes = Counter(), Counter(), Counter()
    status_ctx = {}

    for m in _EVT_CTX.finditer(text):
        if m.group("id") in EVENTS:
            events[m.group("id")] += 1
    if not strict:
        ctx_spans = [m.span("id") for m in _EVT_CTX.finditer(text)]
        for m in _EVT_BARE.finditer(text):
            if m.group(1) in EVENTS and not any(s <= m.start(1) < e for s, e in ctx_spans):
                events[m.group(1)] += 1

    ctx_spans = []
    for m in _HEX_CTX.finditer(text):
        ctx_spans.append(m.span("val"))
        code = _norm_hex(m.group("val"))
        label = re.sub(r"\s+", "", m.group("label")).lower()
        found = lookup_status(code, prefer_kerberos=any(k in label for k in _KRB_LABELS))
        if found:
            statuses[code] += 1
            status_ctx.setdefault(code, set()).add(m.group("label").title())
    if not strict:
        for m in _HEX_BARE.finditer(text):
            if any(s <= m.start() + (2 if m.group(0)[:2].lower() == "0x" else 0) < e
                   for s, e in ctx_spans):
                continue
            has_prefix = m.group(0)[:2].lower() == "0x"
            digits = m.group(1)
            if not has_prefix and len(digits) != 8:
                continue
            code = _norm_hex("0x" + digits)
            if has_prefix or digits[0] in "Cc":
                found = lookup_status(code)
                if found and not (found[0] == "WIN32" and not has_prefix):
                    statuses[code] += 1

    for m in _LOGON_TYPE.finditer(text):
        if m.group(1) in LOGON_TYPES:
            ltypes[m.group(1)] += 1

    ips = Counter(
        v.strip(".:") for v in _SRC_IP.findall(text)
        if v.strip(".:") not in ("-", "::1", "127.0.0.1", "::", "0.0.0.0")
    )
    users = Counter(
        u for u in _USER.findall(text)
        if u not in ("-", "SYSTEM") and not u.endswith("$") and u.lower() != "n/a"
    )
    return {"events": events, "statuses": statuses, "status_ctx": status_ctx,
            "logon_types": ltypes, "ips": ips, "users": users}


def search(term):
    t = term.lower()
    hits = []
    for eid, (desc, sev) in EVENTS.items():
        if t in eid or t in desc.lower():
            hits.append(("EVENT", eid, desc, sev))
    for cat, table in (("NTSTATUS", STATUS), ("KERBEROS", KERBEROS), ("WIN32", WIN32)):
        for k, v in table.items():
            if t in k.lower() or t in v.lower():
                hits.append((cat, k, v, ""))
    for k, v in LOGON_TYPES.items():
        if t in v.lower() or t == k:
            hits.append(("LOGON TYPE", k, v, ""))
    return hits


def build_report(result, source, threshold, timestamp=True):
    rep = Report("LogonLens - Windows authentication analysis", source, timestamp)
    ev_rows = sorted(
        ((eid, EVENTS[eid][0], EVENTS[eid][1], n) for eid, n in result["events"].items()),
        key=lambda r: (_SEV_ORDER.get(r[2], 9), r[0]))
    rep.table("Events", ["Event ID", "Description", "Severity", "Count"],
              [(e, d, f"[{s}]", n) for e, d, s, n in ev_rows], empty="No known event IDs found")

    st_rows = []
    for code, n in sorted(result["statuses"].items(), key=lambda kv: kv[0]):
        found = lookup_status(code, prefer_kerberos=any(
            any(k in c.lower() for k in _KRB_LABELS) for c in result["status_ctx"].get(code, [])))
        cat, desc = found
        field = "/".join(sorted(result["status_ctx"].get(code, []))) or "-"
        st_rows.append((code, cat, field, desc, n))
    rep.table("Status / error codes", ["Code", "Table", "Field", "Meaning", "Count"], st_rows,
              empty="No known status codes found")

    if result["logon_types"]:
        rep.table("Logon types", ["Type", "Meaning", "Count"],
                  [(t, LOGON_TYPES[t], n) for t, n in sorted(result["logon_types"].items(),
                                                              key=lambda kv: int(kv[0]))])
    if result["ips"]:
        rep.table("Source addresses (top 10)", ["Address", "Occurrences"],
                  result["ips"].most_common(10))
    if result["users"]:
        rep.table("Accounts (top 10)", ["Account", "Occurrences"], result["users"].most_common(10))

    notes = []
    if "1102" in result["events"] or "104" in result["events"]:
        notes.append("[CRITICAL] Audit log cleared - treat as possible anti-forensics.")
    fails = result["events"].get("4625", 0) + result["events"].get("4771", 0)
    if fails >= threshold:
        notes.append(f"[WARN] {fails} failed authentications (threshold {threshold}) - "
                     "possible brute force / password spraying.")
        top = [ip for ip, n in result["ips"].most_common(3) if n >= threshold]
        if top:
            notes.append("[WARN] Repeated source addresses: " + ", ".join(top))
    if "4625" in result["events"] and "4624" in result["events"] and \
            fails >= threshold:
        notes.append("[HIGH] Failures and a success are both present - check whether a "
                     "failed run ended in a successful logon.")
    if "0x17" in result["statuses"] and "4768" in result["events"]:
        notes.append("[INFO] 0x17 with a TGT request means password expired; RC4 (0x17 etype) "
                     "in 4769 is a Kerberoasting indicator.")
    if notes:
        rep.lines("Findings", notes)

    crit = sum(n for e, n in result["events"].items() if EVENTS[e][1] in ("CRITICAL", "HIGH"))
    rep.summary = (f"{sum(result['events'].values())} event hits ({len(result['events'])} unique), "
                   f"{len(result['statuses'])} status codes, {crit} high/critical")
    return rep


def search_report(term, hits, timestamp=True):
    rep = Report(f"LogonLens - search '{term}'", "database", timestamp)
    rep.table("Matches", ["Type", "Key", "Description", "Severity"],
              [(c, k, d, f"[{s}]" if s else "") for c, k, d, s in hits], empty="No results found")
    rep.summary = f"{len(hits)} matches"
    return rep


def build_parser():
    p = common.base_parser(
        "logonlens",
        "Decode Windows Event IDs, NTSTATUS/Kerberos codes and logon types from log text.",
        epilog="examples:\n  logonlens 4625 0xC000006A\n"
               "  logonlens -f security.txt --threshold 10 --format md -o report.md\n"
               "  Get-WinEvent ... | Out-String | logonlens\n"
               "  logonlens --search lockout",
    )
    common.add_input_args(p, help_text="event IDs, codes or raw log text (or use -f / stdin)")
    p.add_argument("-s", "--search", metavar="TERM", help="search the built-in database")
    p.add_argument("--threshold", type=int, default=5,
                   help="failed logons before a brute-force finding is raised (default 5)")
    p.add_argument("--strict", action="store_true",
                   help="only match IDs/codes that appear next to a field label")
    p.add_argument("-i", "--interactive", action="store_true", help="interactive prompt")
    common.add_output_args(p)
    return p


def _interactive(args):
    print("LogonLens interactive. Paste log text or codes; 'search TERM', 'quit'.")
    seen = Counter()
    while True:
        try:
            line = input("logonlens> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return common.EXIT_OK
        if not line:
            continue
        if line.lower() in ("quit", "exit"):
            return common.EXIT_OK
        if line.lower().startswith("search "):
            rep = search_report(line[7:].strip(), search(line[7:].strip()), not args.no_timestamp)
        else:
            rep = build_report(analyze(line, args.strict), "interactive", args.threshold,
                               not args.no_timestamp)
        sys.stdout.write(rep.render("text"))


def main(argv=None):
    common.configure_stdio()
    p = build_parser()
    args = p.parse_args(argv)
    if args.interactive:
        return _interactive(args)
    if args.search:
        hits = search(args.search)
        common.emit(search_report(args.search, hits, not args.no_timestamp), args)
        return common.EXIT_OK if hits else common.EXIT_NONE
    try:
        text, source = common.read_input(args)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return common.EXIT_ERROR
    if text is None:
        return common.need_input(p)
    result = analyze(text, args.strict)
    common.emit(build_report(result, source, args.threshold, not args.no_timestamp), args)
    found = result["events"] or result["statuses"] or result["logon_types"]
    return common.EXIT_OK if found else common.EXIT_NONE


if __name__ == "__main__":
    sys.exit(main())
