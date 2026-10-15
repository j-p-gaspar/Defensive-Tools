"""tsconv - convert epoch / FILETIME / WebKit / ISO timestamps to UTC."""
import re
import sys
from datetime import datetime, timedelta, timezone

from . import common
from .report import Report

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_WIN_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_FT_OFFSET = 116444736000000000   # 100ns ticks between 1601 and 1970

FORMATS = ["epoch", "epoch_ms", "epoch_us", "filetime", "webkit", "iso"]


def _from_ticks(n, unit_us, base):
    return base + timedelta(microseconds=n / unit_us)


def detect(value: str):
    """Return (format, datetime) or (None, None)."""
    v = value.strip()
    if re.fullmatch(r"0[xX][0-9a-fA-F]{12,16}", v):
        return "filetime", _from_ticks(int(v, 16), 10, _WIN_EPOCH)
    if re.fullmatch(r"-?\d+(\.\d+)?", v):
        n = float(v)
        digits = len(v.split(".")[0].lstrip("-"))
        if digits <= 11:
            return "epoch", _EPOCH + timedelta(seconds=n)
        if digits <= 14:
            return "epoch_ms", _EPOCH + timedelta(milliseconds=n)
        if digits == 16:
            return "epoch_us", _EPOCH + timedelta(microseconds=n)
        if digits == 17:
            return "webkit", _from_ticks(n, 1, _WIN_EPOCH)
        if digits >= 18:
            return "filetime", _from_ticks(n, 10, _WIN_EPOCH)
        return None, None
    try:
        iso = v.replace("Z", "+00:00").replace(" UTC", "+00:00")
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return "iso", dt.astimezone(timezone.utc)
    except ValueError:
        return None, None


def convert_as(value: str, fmt: str):
    n = float(int(value, 16)) if value.lower().startswith("0x") else float(value)
    return {
        "epoch": lambda: _EPOCH + timedelta(seconds=n),
        "epoch_ms": lambda: _EPOCH + timedelta(milliseconds=n),
        "epoch_us": lambda: _EPOCH + timedelta(microseconds=n),
        "filetime": lambda: _from_ticks(n, 10, _WIN_EPOCH),
        "webkit": lambda: _from_ticks(n, 1, _WIN_EPOCH),
    }[fmt]()


def representations(dt: datetime) -> dict:
    delta = dt - _EPOCH
    micro = delta // timedelta(microseconds=1)
    return {
        "utc": dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "epoch": str(micro // 1_000_000),
        "epoch_ms": str(micro // 1000),
        "filetime": str(micro * 10 + _FT_OFFSET),
        "webkit": str(micro + _FT_OFFSET // 10),
    }


def _tokens(text):
    out = []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}[ T][\d:.]+(\s?(Z|UTC|[+-]\d{2}:?\d{2}))?", ln):
            out.append(ln)
        else:
            out.extend(ln.replace(",", " ").split())
    return out


def main(argv=None):
    common.configure_stdio()
    p = common.base_parser(
        "tsconv", "Convert timestamps (epoch s/ms/us, FILETIME, WebKit, ISO 8601) to UTC.",
        epilog="examples:\n  tsconv 133500000000000000 1700000000 2024-03-01T10:00:00Z\n"
               "  tsconv --as webkit 13350000000000000")
    common.add_input_args(p, help_text="timestamps (or use -f / stdin)")
    p.add_argument("--as", dest="force", choices=FORMATS[:-1],
                   help="force the input format instead of auto-detecting")
    common.add_output_args(p)
    args = p.parse_args(argv)
    try:
        text, source = common.read_input(args)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return common.EXIT_ERROR
    if text is None:
        return common.need_input(p)
    rows, bad = [], 0
    for tok in _tokens(text):
        try:
            if args.force:
                fmt, dt = args.force, convert_as(tok, args.force)
            else:
                fmt, dt = detect(tok)
            if dt is None:
                raise ValueError
            r = representations(dt)
            rows.append((tok, fmt, r["utc"], r["epoch"], r["filetime"]))
        except (ValueError, OverflowError):
            rows.append((tok, "unrecognised", "-", "-", "-"))
            bad += 1
    rep = Report("Timestamp conversion", source, not args.no_timestamp)
    rep.table("Timestamps", ["Input", "Detected as", "UTC", "Epoch (s)", "FILETIME"], rows)
    rep.summary = f"{len(rows) - bad} converted, {bad} unrecognised"
    common.emit(rep, args)
    return common.EXIT_ERROR if bad and bad == len(rows) else common.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
