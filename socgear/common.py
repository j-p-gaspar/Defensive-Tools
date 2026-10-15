"""CLI plumbing shared by every tool: input, output, exit codes, colour."""
import argparse
import os
import sys

EXIT_OK, EXIT_NONE, EXIT_ERROR = 0, 1, 2   # found / nothing found / error


def configure_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def add_input_args(p, positional="items", help_text="input values (or use -f / stdin)"):
    p.add_argument(positional, nargs="*", help=help_text)
    p.add_argument("-f", "--file", action="append", default=[], metavar="FILE",
                   help="read input from FILE ('-' = stdin); may be repeated")


def add_output_args(p):
    g = p.add_argument_group("output")
    g.add_argument("--format", choices=["text", "md", "json", "csv"], default="text",
                   help="output format (default: text, plain ASCII)")
    g.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE")
    g.add_argument("--no-color", action="store_true", help="never emit ANSI colour")
    g.add_argument("--no-timestamp", action="store_true",
                   help="omit the generated time (reproducible output)")


def decode_bytes(raw: bytes) -> str:
    """Decode log exports: UTF-8/UTF-16 (BOM or NUL-interleaved), else latin-1."""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", errors="replace")
    if len(raw) > 1 and raw[1:2] == b"\x00":
        return raw.decode("utf-16-le", errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def read_bytes_input(args, positional="items"):
    """Return (list_of_(label, bytes)), reading args, -f files and piped stdin."""
    chunks = []
    items = getattr(args, positional, None) or []
    if items:
        chunks.append(("arguments", "\n".join(items).encode("utf-8")))
    for fn in args.file:
        if fn == "-":
            chunks.append(("stdin", sys.stdin.buffer.read()))
        else:
            with open(fn, "rb") as fh:
                chunks.append((os.path.basename(fn), fh.read()))
    if not chunks and not sys.stdin.isatty():
        chunks.append(("stdin", sys.stdin.buffer.read()))
    return chunks


def read_input(args, positional="items"):
    """Return (text, source_label), or (None, None) when nothing was supplied."""
    chunks = read_bytes_input(args, positional)
    if not chunks:
        return None, None
    return ("\n".join(decode_bytes(b) for _, b in chunks),
            ", ".join(label for label, _ in chunks))


def use_color(args, fmt="text"):
    if args.no_color or os.environ.get("NO_COLOR") or args.output or fmt != "text":
        return False
    return sys.stdout.isatty()


def emit(report, args):
    """Render and write the report. Results go to stdout/file, nothing else."""
    text = report.render(args.format, color=use_color(args, args.format))
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def need_input(parser):
    parser.print_usage(sys.stderr)
    print("error: no input (give values, -f FILE, or pipe via stdin)", file=sys.stderr)
    return EXIT_ERROR


def base_parser(prog, description, epilog=None):
    return argparse.ArgumentParser(prog=prog, description=description, epilog=epilog,
                                   formatter_class=argparse.RawDescriptionHelpFormatter)
