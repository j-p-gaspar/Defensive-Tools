"""Shared report model and renderers.

Every tool builds a Report and renders it as text, md, json or csv.  The
default text format is plain ASCII with no colour codes so it can be pasted
straight into a ticket or an incident report.
"""
import csv
import io
import json
import re
from datetime import datetime, timezone

RULE = "-" * 72

_SEV_COLORS = {
    "CRITICAL": "\033[1;91m", "HIGH": "\033[91m", "WARN": "\033[93m",
    "INFO": "\033[96m", "OK": "\033[92m",
}
_SEV_RE = re.compile(r"\[(CRITICAL|HIGH|WARN|INFO|OK)\]")


class Report:
    def __init__(self, tool, source="-", timestamp=True):
        self.tool = tool
        self.source = source
        self.generated = (
            datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if timestamp else None
        )
        self.sections = []
        self.summary = ""
        self.data = None   # optional structured payload (json output only)

    # -- builders ----------------------------------------------------------
    def table(self, title, columns, rows, empty="(none)"):
        rows = [[str(c) for c in r] for r in rows]
        self.sections.append(
            {"kind": "table", "title": title, "columns": list(columns), "rows": rows, "empty": empty}
        )

    def lines(self, title, items, empty="(none)"):
        self.sections.append(
            {"kind": "lines", "title": title, "items": [str(i) for i in items], "empty": empty}
        )

    def text(self, title, body):
        self.sections.append({"kind": "text", "title": title, "body": str(body)})

    def kv(self, title, pairs):
        self.sections.append(
            {"kind": "kv", "title": title, "pairs": [(str(k), str(v)) for k, v in pairs]}
        )

    # -- renderers ---------------------------------------------------------
    def _header(self):
        head = [self.tool, f"Source   : {self.source}"]
        if self.generated:
            head.append(f"Generated: {self.generated}")
        return head

    def to_text(self):
        out = self._header() + [RULE]
        for s in self.sections:
            k = s["kind"]
            if k == "table":
                out.append(f"{s['title']} ({len(s['rows'])})")
                if not s["rows"]:
                    out.append(f"  {s['empty']}")
                else:
                    widths = [len(c) for c in s["columns"]]
                    for r in s["rows"]:
                        for i, c in enumerate(r):
                            widths[i] = max(widths[i], len(c))

                    def fmt(cells):
                        parts = [c.ljust(widths[i]) for i, c in enumerate(cells[:-1])]
                        parts.append(cells[-1])
                        return ("  " + "  ".join(parts)).rstrip()

                    out.append(fmt(s["columns"]))
                    out.append("  " + "  ".join("-" * w for w in widths))
                    out.extend(fmt(r) for r in s["rows"])
            elif k == "lines":
                out.append(f"{s['title']} ({len(s['items'])})")
                if s["items"]:
                    out.extend(f"  {i}" for i in s["items"])
                else:
                    out.append(f"  {s['empty']}")
            elif k == "kv":
                out.append(s["title"])
                w = max((len(a) for a, _ in s["pairs"]), default=0)
                out.extend(f"  {a.ljust(w)} : {b}" for a, b in s["pairs"])
            else:
                out.append(s["title"])
                out.extend(("  " + ln).rstrip() for ln in s["body"].splitlines())
            out.append("")
        out.append(RULE)
        if self.summary:
            out.append(f"Summary: {self.summary}")
        return "\n".join(out) + "\n"

    def to_md(self):
        out = [f"# {self.tool}", "", f"- **Source:** {self.source}"]
        if self.generated:
            out.append(f"- **Generated:** {self.generated}")
        out.append("")

        def esc(c):
            return c.replace("|", "\\|").replace("\n", " ")

        for s in self.sections:
            k = s["kind"]
            out += [f"## {s['title']}", ""]
            if k == "table":
                if not s["rows"]:
                    out.append(s["empty"])
                else:
                    out.append("| " + " | ".join(s["columns"]) + " |")
                    out.append("|" + "|".join(" --- " for _ in s["columns"]) + "|")
                    out.extend("| " + " | ".join(esc(c) for c in r) + " |" for r in s["rows"])
            elif k == "lines":
                out += ["```"] + (s["items"] or [s["empty"]]) + ["```"]
            elif k == "kv":
                out.extend(f"- **{a}:** {b}" for a, b in s["pairs"])
            else:
                out += ["```", s["body"], "```"]
            out.append("")
        if self.summary:
            out.append(f"**Summary:** {self.summary}")
        return "\n".join(out) + "\n"

    def to_dict(self):
        secs = []
        for s in self.sections:
            d = {"title": s["title"], "kind": s["kind"]}
            if s["kind"] == "table":
                d["rows"] = [dict(zip(s["columns"], r)) for r in s["rows"]]
            elif s["kind"] == "lines":
                d["items"] = s["items"]
            elif s["kind"] == "kv":
                d["pairs"] = dict(s["pairs"])
            else:
                d["body"] = s["body"]
            secs.append(d)
        out = {"tool": self.tool, "source": self.source, "generated": self.generated,
               "summary": self.summary, "sections": secs}
        if self.data is not None:
            out["data"] = self.data
        return out

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"

    def to_csv(self):
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        for s in self.sections:
            if s["kind"] == "table":
                w.writerow(["section"] + s["columns"])
                for r in s["rows"]:
                    w.writerow([s["title"]] + r)
            elif s["kind"] == "lines":
                w.writerow(["section", "value"])
                for i in s["items"]:
                    w.writerow([s["title"], i])
            elif s["kind"] == "kv":
                w.writerow(["section", "key", "value"])
                for a, b in s["pairs"]:
                    w.writerow([s["title"], a, b])
            else:
                w.writerow(["section", "text"])
                w.writerow([s["title"], s["body"]])
        return buf.getvalue()

    def render(self, fmt="text", color=False):
        out = {"text": self.to_text, "md": self.to_md, "json": self.to_json,
               "csv": self.to_csv}[fmt]()
        if color and fmt == "text":
            out = _SEV_RE.sub(lambda m: f"{_SEV_COLORS[m.group(1)]}{m.group(0)}\033[0m", out)
        return out
