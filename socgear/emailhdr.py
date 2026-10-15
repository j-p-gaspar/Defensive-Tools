"""emailhdr - parse raw email headers for phishing triage."""
import re
import sys
from email.parser import HeaderParser
from email.utils import getaddresses, parsedate_to_datetime

from . import common
from .ipparser import extract_ips
from .report import Report

_AUTH = re.compile(r"\b(spf|dkim|dmarc|arc)\s*=\s*([a-z]+)", re.I)


def _domain(addr_header):
    addrs = getaddresses([addr_header or ""])
    for _, a in addrs:
        if "@" in a:
            return a.rsplit("@", 1)[1].lower().strip(">")
    return ""


def parse(raw: str) -> dict:
    msg = HeaderParser().parsestr(raw)
    hops = []
    for i, rec in enumerate(reversed(msg.get_all("Received", []) or []), 1):
        rec = " ".join(rec.split())
        when = rec.rsplit(";", 1)[-1].strip() if ";" in rec else ""
        try:
            when = parsedate_to_datetime(when).strftime("%Y-%m-%d %H:%M:%S %z")
        except (TypeError, ValueError):
            pass
        frm = re.search(r"\bfrom\s+(\S+)", rec, re.I)
        by = re.search(r"\bby\s+(\S+)", rec, re.I)
        ips = [v for v, _, t in extract_ips(rec.split(";")[0]) if t == "public"]
        hops.append((i, frm.group(1) if frm else "-", by.group(1).rstrip(";") if by else "-",
                     ", ".join(ips) or "-", when or "-"))
    auth = {}
    for h in (msg.get_all("Authentication-Results", []) or []) + \
             (msg.get_all("Received-SPF", []) or []):
        for k, v in _AUTH.findall(h):
            auth.setdefault(k.lower(), v.lower())
    spf_hdr = msg.get("Received-SPF", "")
    if "spf" not in auth and spf_hdr:
        auth["spf"] = spf_hdr.split()[0].lower()
    fields = [(k, " ".join((msg.get(k) or "").split())) for k in
              ("From", "To", "Subject", "Date", "Message-ID", "Return-Path", "Reply-To",
               "X-Originating-IP", "X-Mailer", "User-Agent")]
    fields = [(k, v) for k, v in fields if v]
    findings = []
    from_d, ret_d, rep_d = _domain(msg.get("From")), _domain(msg.get("Return-Path")), \
        _domain(msg.get("Reply-To"))
    if from_d and ret_d and from_d != ret_d:
        findings.append(f"[WARN] From domain ({from_d}) differs from Return-Path ({ret_d})")
    if from_d and rep_d and from_d != rep_d:
        findings.append(f"[WARN] Reply-To domain ({rep_d}) differs from From ({from_d})")
    for mech in ("spf", "dkim", "dmarc"):
        res = auth.get(mech)
        if res is None:
            findings.append(f"[INFO] No {mech.upper()} result found in headers")
        elif res != "pass":
            findings.append(f"[HIGH] {mech.upper()} = {res}")
    if not hops:
        findings.append("[INFO] No Received headers present")
    return {"fields": fields, "hops": hops, "auth": auth, "findings": findings}


def main(argv=None):
    common.configure_stdio()
    p = common.base_parser(
        "emailhdr", "Parse raw email headers: routing hops, SPF/DKIM/DMARC, spoofing hints.",
        epilog="examples:\n  emailhdr -f suspicious.eml\n  cat headers.txt | emailhdr --format md")
    common.add_input_args(p, help_text="header text (or use -f / stdin)")
    common.add_output_args(p)
    args = p.parse_args(argv)
    try:
        text, source = common.read_input(args)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return common.EXIT_ERROR
    if text is None:
        return common.need_input(p)
    head = re.split(r"\r?\n\r?\n", text.strip(), maxsplit=1)[0]
    r = parse(head)
    rep = Report("Email header analysis", source, not args.no_timestamp)
    rep.kv("Message", r["fields"])
    rep.table("Delivery path (oldest hop first)", ["#", "From", "By", "Public IP", "Time"],
              r["hops"], empty="No Received headers")
    rep.kv("Authentication", [(k.upper(), v) for k, v in r["auth"].items()] or [("(none)", "-")])
    rep.lines("Findings", r["findings"])
    bad = sum(1 for f in r["findings"] if f.startswith(("[HIGH]", "[WARN]")))
    rep.summary = f"{len(r['hops'])} hops, {bad} warning(s)"
    common.emit(rep, args)
    return common.EXIT_OK if r["fields"] else common.EXIT_NONE


if __name__ == "__main__":
    sys.exit(main())
