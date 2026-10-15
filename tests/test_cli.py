"""CLI-level tests for the socgear tools (call main() and inspect stdout / exit code)."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from socgear import emailhdr, fangvault, hashfile, ipparser, iocx, logonlens, tsconv  # noqa: E402
from socgear.report import Report  # noqa: E402


def run(mod, argv, capsys):
    code = mod.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


# -- report -------------------------------------------------------------------

def test_report_text_is_plain_ascii_without_ansi():
    r = Report("T", "src", timestamp=False)
    r.table("Things", ["A", "B"], [("1", "two"), ("3", "four")])
    r.summary = "done"
    out = r.render("text", color=False)
    assert "\033" not in out
    assert all(ord(c) < 128 for c in out)
    assert "Summary: done" in out
    assert all(not ln.endswith(" ") for ln in out.splitlines())


def test_report_formats_roundtrip():
    r = Report("T", "src", timestamp=False)
    r.table("Things", ["A", "B"], [("1", "x|y")])
    assert json.loads(r.render("json"))["sections"][0]["rows"][0] == {"A": "1", "B": "x|y"}
    assert "x\\|y" in r.render("md")
    assert r.render("csv").splitlines()[0] == "section,A,B"


# -- ip parser ----------------------------------------------------------------

def test_ip_extracts_valid_and_rejects_invalid():
    ips = [v for v, _, _ in ipparser.extract_ips("a 10.0.0.1 b 999.1.1.1 c 8.8.8.8 d 8.8.8.8")]
    assert ips == ["10.0.0.1", "8.8.8.8"]


def test_ip_handles_defanged_and_ipv6():
    got = {v: t for v, _, t in ipparser.extract_ips("1[.]1[.]1[.]1 and 2001:4860:4860::8888")}
    assert got["1.1.1.1"] == "public"
    assert "2001:4860:4860::8888" in got


def test_ip_counts_and_filters(capsys):
    code, out, _ = run(ipparser, ["-q", "--public-only", "10.0.0.1 8.8.8.8 1.1.1.1"], capsys)
    assert code == 0 and out.split() == ["8.8.8.8", "1.1.1.1"]


def test_ip_exit_code_when_nothing_found(capsys):
    code, _, _ = run(ipparser, ["no addresses here", "--no-timestamp"], capsys)
    assert code == 1


def test_ip_multiline_file(tmp_path, capsys):
    f = tmp_path / "log.txt"
    f.write_text("line1 1.2.3.4\nline2 5.6.7.8\nline3 1.2.3.4\n")
    code, out, _ = run(ipparser, ["-f", str(f), "-q"], capsys)
    assert out.split() == ["1.2.3.4", "5.6.7.8"]


# -- logonlens ----------------------------------------------------------------

def test_logon_no_false_positives_on_words_and_years():
    r = logonlens.analyze("Deployed DEADBEEF facade on 2024 port 8080 at 12:30:45")
    assert not r["events"] and not r["statuses"]


def test_logon_context_and_bare_codes():
    r = logonlens.analyze("EventID: 4625 Status: 0xC000006D SubStatus: 0xC000006A")
    assert r["events"]["4625"] == 1
    assert set(r["statuses"]) == {"0xC000006D", "0xC000006A"}
    r = logonlens.analyze("0xC0000234 4740")
    assert "0xC0000234" in r["statuses"] and "4740" in r["events"]


def test_logon_kerberos_codes_are_correct():
    assert "PREAUTH_FAILED" in logonlens.KERBEROS["0x18"]
    assert "KEY_EXPIRED" in logonlens.KERBEROS["0x17"]
    cat, _ = logonlens.lookup_status("0x18", prefer_kerberos=True)
    assert cat == "KERBEROS"


def test_logon_cli_brute_force_finding(capsys):
    text = "Event ID: 4625 Source Network Address: 9.9.9.9\n" * 6
    code, out, _ = run(logonlens, [text, "--no-timestamp"], capsys)
    assert code == 0 and "brute force" in out and "9.9.9.9" in out


def test_logon_search(capsys):
    code, out, _ = run(logonlens, ["--search", "lockout", "--no-timestamp"], capsys)
    assert code == 0 and "4740" in out
    code, _, _ = run(logonlens, ["--search", "zzzz-none", "--no-timestamp"], capsys)
    assert code == 1


# -- iocx ---------------------------------------------------------------------

def test_iocx_extracts_all_types():
    text = ("hxxps[://]evil[.]com/a.exe 1.2.3.4 bad[@]evil.org CVE-2023-0001 "
            "d41d8cd98f00b204e9800998ecf8427e")
    got = {(k, v) for k, v, _ in iocx.extract(text)}
    assert ("url", "https://evil.com/a.exe") in got
    assert ("ip", "1.2.3.4") in got
    assert ("email", "bad@evil.org") in got
    assert ("cve", "CVE-2023-0001") in got
    assert ("md5", "d41d8cd98f00b204e9800998ecf8427e") in got


def test_iocx_skips_filenames_as_domains():
    domains = [v for k, v, _ in iocx.extract("run payload.exe then notes.txt, see evil.com")
               if k == "domain"]
    assert domains == ["evil.com"]


def test_iocx_unknown_type_is_error(capsys):
    code, _, err = run(iocx, ["-t", "bogus", "x"], capsys)
    assert code == 2 and "unknown type" in err


# -- tsconv -------------------------------------------------------------------

@pytest.mark.parametrize("value,fmt", [
    ("1700000000", "epoch"), ("1700000000000", "epoch_ms"),
    ("133444736000000000", "filetime"), ("13344473600000000", "webkit"),
    ("2023-11-14T22:13:20Z", "iso"),
])
def test_tsconv_detect(value, fmt):
    f, dt = tsconv.detect(value)
    assert f == fmt
    assert (dt.year, dt.month, dt.day) == (2023, 11, 14)


def test_tsconv_cli(capsys):
    code, out, _ = run(tsconv, ["1700000000", "--no-timestamp"], capsys)
    assert code == 0 and "2023-11-14 22:13:20 UTC" in out


# -- email headers ------------------------------------------------------------

def test_emailhdr_flags_spoofing_and_auth():
    r = emailhdr.parse(
        "From: a@good.com\nReturn-Path: <x@evil.com>\n"
        "Received: from m.evil.com (8.8.4.4) by mx.good.com; Tue, 1 Mar 2022 10:00:00 +0000\n"
        "Authentication-Results: mx; spf=fail; dkim=pass; dmarc=fail\n")
    joined = "\n".join(r["findings"])
    assert "Return-Path" in joined and "SPF = fail" in joined and "DMARC = fail" in joined
    assert r["hops"][0][3] == "8.8.4.4"


# -- hashfile / fangvault CLI -------------------------------------------------

def test_hashfile(tmp_path, capsys):
    f = tmp_path / "a.bin"
    f.write_bytes(b"abc")
    _, out, _ = run(hashfile, ["-q", str(f)], capsys)
    assert out.startswith("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


def test_hashfile_missing_file(capsys):
    code, _, err = run(hashfile, ["does-not-exist.bin"], capsys)
    assert code == 2 and "does-not-exist.bin" in err


def test_fangvault_defang_fang_roundtrip(capsys):
    _, out, _ = run(fangvault, ["defang", "http://evil.com/a.exe", "--format", "json",
                                "--no-timestamp"], capsys)
    rows = json.loads(out)["sections"][0]["rows"]
    assert rows[0]["Indicator"] == "hxxp[://]evil[.]com/a[.]exe"
    _, out, _ = run(fangvault, ["fang", rows[0]["Indicator"], "--no-timestamp"], capsys)
    assert "http://evil.com/a.exe" in out


def test_fangvault_defang_only_rewrites_scheme(capsys):
    _, out, _ = run(fangvault, ["defang", "http://x.com/http-check", "--no-timestamp"], capsys)
    assert "hxxp[://]x[.]com/http-check" in out


def test_fangvault_decode_and_shell_exit_codes(capsys):
    code, out, _ = run(fangvault, ["decode", "http://x.io/?q=aGVsbG8gd29ybGQ=", "--no-timestamp"], capsys)
    assert code == 0 and "hello world" in out
    code, _, _ = run(fangvault, ["decode", "http://x.io/plain", "--no-timestamp"], capsys)
    assert code == 1
    code, out, _ = run(fangvault, ["shell", "http://x.io/a?cmd=powershell", "--no-timestamp"], capsys)
    assert code == 0 and "PowerShell" in out


def test_output_file(tmp_path, capsys):
    out = tmp_path / "r.md"
    _, stdout, _ = run(ipparser, ["1.2.3.4", "--format", "md", "-o", str(out)], capsys)
    assert stdout == "" and out.read_text().startswith("# IP Parser")
