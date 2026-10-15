import pytest
import json
import base64
import codecs
import importlib.util

# ── Load module ───────────────────────────────────────────────────────────────
spec = importlib.util.spec_from_file_location("defang", "FangVault.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# ── Issue #1 — Detection Order: Base64 with %3D padding ──────────────────────

def test_base64_with_encoded_padding():
    assert mod._detect("aGVsbG8%3D") == "Base64"

def test_base64_with_lowercase_encoded_padding():
    assert mod._detect("aGVsbG8%3d") == "Base64"

def test_real_url_encoding_still_detected():
    assert mod._detect("%41%42%43") == "URL-encoded"

def test_mixed_url_encoding_not_base64():
    assert mod._detect("hello%20world") == "URL-encoded"

def test_base64_decoded_correctly_via_chain():
    result, label, _ = mod.detect_and_decode("aGVsbG8%3D")
    assert result == "hello"
    assert "Base64" in label


# ── Issue #2 — ROT13 detection ────────────────────────────────────────────────

def test_rot13_powershell_url():
    encoded = codecs.encode("https://malware.com/payload.ps1", "rot_13")
    assert mod._detect(encoded) == "ROT13"

def test_rot13_exe_dropper():
    encoded = codecs.encode("cmd.exe /c download.bat", "rot_13")
    assert mod._detect(encoded) == "ROT13"

def test_rot13_decodes_correctly():
    encoded = codecs.encode("powershell -EncodedCommand", "rot_13")
    result, label, layers = mod.detect_and_decode(encoded)
    assert result == "powershell -EncodedCommand"
    assert "ROT13" in label

def test_plain_english_not_rot13():
    assert mod._detect("the quick brown fox") != "ROT13"


# ── Issue #3 — Base64 printable-output heuristic ─────────────────────────────

def test_printable_base64_accepted():
    assert mod.is_base64("aGVsbG8gd29ybGQ=") is True

def test_binary_base64_rejected():
    raw = bytes(range(0, 64))
    b64 = base64.b64encode(raw).decode()
    assert mod.is_base64(b64) is False

def test_url_payload_base64_accepted():
    payload = base64.b64encode(b"https://evil.com/shell.ps1").decode()
    assert mod.is_base64(payload) is True


# ── Issue #4 — Unicode escape decoder ────────────────────────────────────────

def test_basic_ascii_unicode_escape():
    result = mod._run_decoder("Unicode escape", "\\u0041\\u0042\\u0043")
    assert result == "ABC"

def test_detect_unicode_escape():
    s = "\\u0068\\u0065\\u006C\\u006C\\u006F"
    assert mod._detect(s) == "Unicode escape"

def test_unicode_escape_full_decode():
    s = "\\u0068\\u0065\\u006C\\u006C\\u006F"
    result, _, _ = mod.detect_and_decode(s)
    assert result == "hello"


# ── Issue #5 — JWT detection ──────────────────────────────────────────────────

@pytest.fixture
def sample_jwt():
    return (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

def test_jwt_detected(sample_jwt):
    assert mod._detect(sample_jwt) == "JWT"

def test_jwt_decode_payload(sample_jwt):
    data = mod.decode_jwt(sample_jwt)
    assert data["payload"].get("sub") == "1234567890"


# ── Issue #7 — Punycode / IDN decoding ───────────────────────────────────────

def test_punycode_hostname_decoded():
    assert mod.decode_punycode("xn--googl-hwe.com") is not None

def test_idn_warning_in_full_url_decode():
    result = mod.decode_url_full("https://xn--googl-hwe.com/path")
    assert "__idn_warning__" in result
    assert "homograph" in result["__idn_warning__"]["note"].lower()


# ── Issue #8 — Path traversal / IOC flag detection ───────────────────────────

@pytest.mark.parametrize("path, expected_flag", [
    ("/admin/../etc/passwd", "directory traversal (../)"),
    ("/admin%2Fetc%2Fpasswd", "URL-encoded slash (%2F)"),
    ("/admin%252Fetc", "double-encoded slash (%252F)"),
    ("/file.php%00.jpg", "null byte (%00)"),
])
def test_path_traversal_flags(path, expected_flag):
    flags = mod.check_path_traversal(path)
    assert expected_flag in flags


# ── Regression — core defang/fang ─────────────────────────────────────────────

def test_defang_ipv4():
    defanged, kind = mod.defang("192.168.1.1")
    assert defanged == "192[.]168[.]1[.]1"
    assert kind == "IP"

def test_fang_url_basic():
    fanged, kind = mod.fang("hxxp[://]malware[.]com/test[.]php")
    assert fanged == "http://malware.com/test.php"
    assert kind == "URL"


# ── IP Metadata & File Intent ────────────────────────────────────────────────

def test_get_ip_metadata_private():
    tags = mod.get_ip_metadata("192[.]168[.]1[.]50")
    assert "PRIVATE / INTERNAL IP" in tags

def test_check_file_intent_dangerous():
    assert "DANGEROUS FILE" in mod.check_file_intent("/payload.exe")
    assert "IMAGE FILE" in mod.check_file_intent("/logo.png")


# ── Integration ───────────────────────────────────────────────────────────────

def test_decode_url_full_integration():
    url = "http://10.0.0.5/downloads/malware.exe?encoded=YWRtaW4="
    results = mod.decode_url_full(url)
    
    assert "__network_warning__" in results
    assert "PRIVATE / INTERNAL IP" in results["__network_warning__"]
    assert "DANGEROUS FILE: .exe" in results["path"]["file_intent"]
    assert results["query_params"]["param 'encoded'"]["decoded"] == "admin"