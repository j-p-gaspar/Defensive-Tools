"""ip_parser - extract unique, validated IPv4/IPv6 addresses from any text."""
import ipaddress
import re
import sys

from . import common
from .report import Report

_SEP = r"(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\.)"
_IPV4_RE = re.compile(
    r"(?<![\w.])(\d{1,3})" + "".join(rf"{_SEP}(\d{{1,3}})" for _ in range(3))
    + r"(?:/(\d{1,2}))?(?![\w]|\.\d)",
    re.IGNORECASE,
)
_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:\[?)((?:[0-9A-Fa-f]{0,4}(?:\[:\]|:)){2,7}[0-9A-Fa-f]{0,4})"
    r"(?:/(\d{1,3}))?(?![0-9A-Fa-f:])"
)


def classify(ip) -> str:
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    return "public"


def extract_ips(text, include_v6=True):
    """Return [(value, count, type)] in first-seen order. Handles defanged input."""
    found = {}   # value -> [first_pos, count, type]

    def add(pos, value, kind):
        if value in found:
            found[value][1] += 1
        else:
            found[value] = [pos, 1, kind]

    for m in _IPV4_RE.finditer(text):
        octets = [int(g) for g in m.groups()[:4]]
        if any(o > 255 for o in octets):
            continue
        addr = ".".join(map(str, octets))
        prefix = m.group(5)
        try:
            if prefix is not None:
                net = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
                add(m.start(), f"{addr}/{prefix}", classify(net.network_address))
            else:
                add(m.start(), addr, classify(ipaddress.ip_address(addr)))
        except ValueError:
            continue

    if include_v6:
        for m in _IPV6_RE.finditer(text):
            cand = m.group(1).replace("[:]", ":")
            if cand.strip(":") == "":
                continue
            try:
                ip = ipaddress.IPv6Address(cand)
            except ValueError:
                continue
            value = str(ip)
            if m.group(2):
                value += "/" + m.group(2)
            add(m.start(), value, classify(ip))

    return [(v, c, k) for v, (_, c, k) in sorted(found.items(), key=lambda kv: kv[1][0])]


def extract_unique_ips(text):
    """Backwards compatible helper: (list_of_unique_ips, count)."""
    ips = [v for v, _, _ in extract_ips(text)]
    return ips, len(ips)


def _sort_key(item):
    value = item[0].split("/")[0]
    ip = ipaddress.ip_address(value)
    return (ip.version, int(ip))


def defang(value):
    return value.replace(".", "[.]").replace(":", "[:]")


def build_parser():
    p = common.base_parser(
        "ip_parser",
        "Extract unique IPv4/IPv6 addresses (including defanged and CIDR) from text.",
        epilog="examples:\n  ip_parser -f firewall.log --public-only\n"
               "  cat headers.txt | ip_parser --counts --format md\n"
               "  ip_parser -q -f alerts.txt | sort -u",
    )
    common.add_input_args(p, help_text="text to scan (or use -f / stdin)")
    p.add_argument("--public-only", action="store_true", help="keep only public addresses")
    p.add_argument("--exclude-private", action="store_true",
                   help="drop private, loopback, link-local, multicast and reserved")
    p.add_argument("--only-private", action="store_true", help="keep only non-public addresses")
    p.add_argument("--no-ipv6", action="store_true", help="ignore IPv6")
    p.add_argument("--sort", action="store_true", help="sort numerically (default: first seen)")
    p.add_argument("--defang", action="store_true", help="defang the output (1[.]2[.]3[.]4)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="print only the addresses, one per line (for piping)")
    common.add_output_args(p)
    return p


def main(argv=None):
    common.configure_stdio()
    p = build_parser()
    args = p.parse_args(argv)
    try:
        text, source = common.read_input(args)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return common.EXIT_ERROR
    if text is None:
        return common.need_input(p)

    rows = extract_ips(text, include_v6=not args.no_ipv6)
    total_found = len(rows)
    if args.public_only:
        rows = [r for r in rows if r[2] == "public"]
    elif args.exclude_private:
        rows = [r for r in rows if r[2] == "public"]
    if args.only_private:
        rows = [r for r in rows if r[2] != "public"]
    if args.sort:
        rows.sort(key=_sort_key)

    shown = [(defang(v) if args.defang else v, c, k) for v, c, k in rows]
    if args.quiet:
        for v, _, _ in shown:
            print(v)
        return common.EXIT_OK if shown else common.EXIT_NONE

    rep = Report("IP Parser - unique IP addresses", source, not args.no_timestamp)
    rep.table("Unique IP addresses", ["IP", "Count", "Type"], shown, empty="No IP addresses found")
    by_type = {}
    for _, _, k in rows:
        by_type[k] = by_type.get(k, 0) + 1
    breakdown = ", ".join(f"{n} {k}" for k, n in sorted(by_type.items()))
    rep.summary = f"{len(rows)} unique IPs" + (f" ({breakdown})" if breakdown else "")
    if total_found != len(rows):
        rep.summary += f"; {total_found - len(rows)} filtered out"
    common.emit(rep, args)
    return common.EXIT_OK if rows else common.EXIT_NONE


if __name__ == "__main__":
    sys.exit(main())
