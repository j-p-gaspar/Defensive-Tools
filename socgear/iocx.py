"""iocx - extract IOCs (IPs, URLs, domains, emails, hashes, CVEs) from any text."""
import re
import sys

from . import common
from .ipparser import extract_ips
from .report import Report

_REFANG = [
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[\s*://\s*\]|\[:\]//|\[://\]"), "://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[@\]|\(@\)|\[at\]|\(at\)", re.I), "@"),
]
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`\\^{}|]+", re.I)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
_HASH_RES = {
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
}
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
# Strings that look like domains but are file names / code.
_NOT_TLD = {
    "exe", "dll", "txt", "log", "py", "js", "json", "xml", "csv", "html", "htm", "php", "asp",
    "aspx", "jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "xls", "xlsx", "ps1", "bat", "sh",
    "zip", "rar", "gz", "tar", "md", "yml", "yaml", "ini", "cfg", "conf", "tmp", "bak", "sys",
    "evtx", "msi", "lnk", "vbs", "jar", "class", "so", "cs", "cpp", "java", "rb", "go", "rs",
}
TYPES = ["ip", "url", "domain", "email", "md5", "sha1", "sha256", "cve"]


def refang_text(text: str) -> str:
    for rx, repl in _REFANG:
        text = rx.sub(repl, text)
    return text


def _add(store, kind, value, norm=None):
    key = (kind, norm or value)
    if key in store:
        store[key][1] += 1
    else:
        store[key] = [value, 1]


def extract(text: str, types=None) -> list[tuple[str, str, int]]:
    """Return [(type, value, count)] ordered by type then first appearance."""
    want = set(types or TYPES)
    text = refang_text(text)
    store = {}
    url_spans = []
    for m in _URL_RE.finditer(text):
        url_spans.append(m.span())
        if "url" in want:
            _add(store, "url", m.group(0).rstrip(".,;:)]'\""))
    if "ip" in want:
        for v, c, _ in extract_ips(text):
            for _ in range(c):
                _add(store, "ip", v)
    emails = set()
    for m in _EMAIL_RE.finditer(text):
        emails.add(m.group(0).lower())
        if "email" in want:
            _add(store, "email", m.group(0).lower())
    if "domain" in want:
        for m in _DOMAIN_RE.finditer(text):
            d = m.group(0).lower()
            tld = d.rsplit(".", 1)[-1]
            if tld in _NOT_TLD or tld.isdigit() or re.fullmatch(r"[\d.]+", d):
                continue
            if any(d == e.split("@", 1)[1] and False for e in emails):
                continue
            _add(store, "domain", d)
    taken = []
    for name in ("sha256", "sha1", "md5"):
        if name not in want:
            continue
        for m in _HASH_RES[name].finditer(text):
            if any(s <= m.start() < e for s, e in taken):
                continue
            _add(store, name, m.group(0).lower())
        taken += [m.span() for m in _HASH_RES[name].finditer(text)]
    if "cve" in want:
        for m in _CVE_RE.finditer(text):
            _add(store, "cve", m.group(0).upper())
    order = {t: i for i, t in enumerate(TYPES)}
    items = [(k[0], v[0], v[1]) for k, v in store.items()]
    items.sort(key=lambda r: order[r[0]])   # stable: first appearance within a type
    return items


def _defang(kind, value):
    if kind in ("url",):
        return re.sub(r"^(https?|ftp)", lambda m: m.group(1).replace("http", "hxxp"), value,
                      flags=re.I).replace("://", "[://]").replace(".", "[.]")
    if kind in ("ip", "domain"):
        return value.replace(".", "[.]").replace(":", "[:]")
    if kind == "email":
        return value.replace("@", "[@]").replace(".", "[.]")
    return value


def build_parser():
    p = common.base_parser(
        "iocx", "Extract IOCs from text: IPs, URLs, domains, emails, hashes and CVEs.",
        epilog="examples:\n  iocx -f report.txt --defang --format md\n"
               "  iocx -t ip,sha256 -q -f alert.json\n  cat phishing.eml | iocx --format csv")
    common.add_input_args(p, help_text="text to scan (or use -f / stdin)")
    p.add_argument("-t", "--types", help="comma list: " + ",".join(TYPES))
    p.add_argument("--defang", action="store_true", help="defang values in the output")
    p.add_argument("-q", "--quiet", action="store_true", help="print only the values")
    common.add_output_args(p)
    return p


def main(argv=None):
    common.configure_stdio()
    p = build_parser()
    args = p.parse_args(argv)
    types = None
    if args.types:
        types = [t.strip().lower() for t in args.types.split(",") if t.strip()]
        bad = [t for t in types if t not in TYPES]
        if bad:
            print(f"error: unknown type(s): {', '.join(bad)}", file=sys.stderr)
            return common.EXIT_ERROR
    try:
        text, source = common.read_input(args)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return common.EXIT_ERROR
    if text is None:
        return common.need_input(p)
    rows = [(k, _defang(k, v) if args.defang else v, c) for k, v, c in extract(text, types)]
    if args.quiet:
        for _, v, _ in rows:
            print(v)
        return common.EXIT_OK if rows else common.EXIT_NONE
    rep = Report("IOCX - indicator extraction", source, not args.no_timestamp)
    for kind in TYPES:
        sel = [(v, c) for k, v, c in rows if k == kind]
        if sel:
            rep.table(kind.upper() if len(kind) <= 6 else kind, ["Value", "Count"], sel)
    if not rows:
        rep.lines("Indicators", [], empty="No indicators found")
    counts = {k: sum(1 for r in rows if r[0] == k) for k in TYPES}
    rep.summary = ", ".join(f"{n} {k}" for k, n in counts.items() if n) or "no indicators"
    common.emit(rep, args)
    return common.EXIT_OK if rows else common.EXIT_NONE


if __name__ == "__main__":
    sys.exit(main())
