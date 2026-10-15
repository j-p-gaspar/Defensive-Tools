"""socgear - umbrella command: `socgear <tool> [args]`."""
import importlib
import sys

from . import __version__

TOOLS = {
    "fangvault": ("fangvault", "defang/refang IOCs, decode obfuscation, webshell scan"),
    "ip":        ("ipparser",  "extract unique IPv4/IPv6 addresses"),
    "logon":     ("logonlens", "decode Windows event IDs / NTSTATUS / Kerberos codes"),
    "ioc":       ("iocx",      "extract IPs, URLs, domains, emails, hashes, CVEs"),
    "time":      ("tsconv",    "convert epoch / FILETIME / WebKit timestamps"),
    "hash":      ("hashfile",  "hash files (MD5/SHA1/SHA256)"),
    "header":    ("emailhdr",  "parse email headers for phishing triage"),
}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(f"socgear {__version__} - SOC analyst toolkit\n\nusage: socgear <tool> [args]\n")
        for name, (_, desc) in TOOLS.items():
            print(f"  {name:<10} {desc}")
        print("\nRun 'socgear <tool> -h' for tool help.")
        return 0 if argv else 2
    if argv[0] in ("-V", "--version"):
        print(__version__)
        return 0
    if argv[0] not in TOOLS:
        print(f"error: unknown tool '{argv[0]}' (choose from: {', '.join(TOOLS)})", file=sys.stderr)
        return 2
    mod = importlib.import_module(f"socgear.{TOOLS[argv[0]][0]}")
    return mod.main(argv[1:])


if __name__ == "__main__":
    sys.exit(main())
