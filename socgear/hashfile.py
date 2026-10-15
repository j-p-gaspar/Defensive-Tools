"""hashfile - hash files (MD5/SHA1/SHA256) for triage; never uploads anything."""
import hashlib
import os
import sys

from . import common
from .report import Report


def hash_file(path, chunk=1 << 20):
    h = {n: hashlib.new(n) for n in ("md5", "sha1", "sha256")}
    size = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            size += len(block)
            for x in h.values():
                x.update(block)
    return size, {n: x.hexdigest() for n, x in h.items()}


def main(argv=None):
    common.configure_stdio()
    p = common.base_parser(
        "hashfile", "Compute MD5/SHA1/SHA256 of files and print lookup links (no network access).",
        epilog="examples:\n  hashfile suspicious.exe dropper.dll\n  hashfile -q --algo sha256 *.exe")
    p.add_argument("files", nargs="+", help="files to hash")
    p.add_argument("--algo", choices=["md5", "sha1", "sha256"], help="print only this hash")
    p.add_argument("-q", "--quiet", action="store_true", help="'<hash>  <file>' lines only")
    common.add_output_args(p)
    args = p.parse_args(argv)
    rep = Report("File hashes", f"{len(args.files)} file(s)", not args.no_timestamp)
    ok, err = 0, 0
    for path in args.files:
        try:
            size, hs = hash_file(path)
        except OSError as e:
            print(f"error: {path}: {e.strerror or e}", file=sys.stderr)
            err += 1
            continue
        ok += 1
        if args.quiet:
            print(f"{hs[args.algo or 'sha256']}  {path}")
            continue
        algos = [args.algo] if args.algo else ["md5", "sha1", "sha256"]
        pairs = [("Size", f"{size} bytes")] + [(a.upper(), hs[a]) for a in algos]
        if "sha256" in algos:
            pairs.append(("VirusTotal", f"https://www.virustotal.com/gui/file/{hs['sha256']}"))
        rep.kv(os.path.basename(path), pairs)
    if not args.quiet:
        rep.summary = f"{ok} hashed, {err} failed"
        common.emit(rep, args)
    return common.EXIT_ERROR if err and not ok else common.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
