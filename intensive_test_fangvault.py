import pytest
import json
import base64
import codecs
import importlib.util
from urllib.parse import quote

# ── Load module dynamically ───────────────────────────────────────────────────
spec = importlib.util.spec_from_file_location("mod", "FangVault.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# ── 1. Defang & Fang (Core Functions & Edge Cases) ───────────────────────────

class TestDefangFang:
    @pytest.mark.parametrize("input_str, expected_val, expected_type", [
        ("192.168.1.1", "192[.]168[.]1[.]1", "IP"),
        ("10.0.0.1:8080", "10[.]0[.]0[.]1[:]8080", "IP"),
        ("https://evil.com/malware.exe", "hxxps[://]evil[.]com/malware[.]exe", "URL"),
        ("http://192.168.1.1/payload", "hxxp[://]192[.]168[.]1[.]1/payload", "URL"),
        ("evil.com", "evil[.]com", "URL"),
        ("", None, None),
        (None, None, None),
        ("   http://spaces.com   ", "hxxp[://]spaces[.]com", "URL")
    ])
    def test_defang_variations(self, input_str, expected_val, expected_type):
        val, vtype = mod.defang(input_str)
        assert val == expected_val
        assert vtype == expected_type

    @pytest.mark.parametrize("input_str, expected_val, expected_type", [
        ("192[.]168[.]1[.]1", "192.168.1.1", "IP"),
        ("10[.]0[.]0[.]1[:]8080", "10.0.0.1:8080", "IP"),
        ("hxxps[://]evil[.]com/malware[.]exe", "https://evil.com/malware.exe", "URL"),
        ("hxxp[://]192[.]168[.]1[.]1/payload", "http://192.168.1.1/payload", "URL"),
        ("", None, None),
        (None, None, None)
    ])
    def test_fang_variations(self, input_str, expected_val, expected_type):
        val, vtype = mod.fang(input_str)
        assert val == expected_val
        assert vtype == expected_type

    @pytest.mark.parametrize("input_str, should_be_valid, expected_issues", [
        ("hxxps[://]evil[.]com", True, []),
        ("https://evil[.]com", False, ["protocol not defanged — 'http' should be 'hxxp'", "contains undefanged '://' — should be '[://]'"]),
        ("hxxps[://]evil.com", False, ["contains undefanged '.' — should be '[.]'"]),
        ("http://evil.com", False, ["contains undefanged '.' — should be '[.]'", "contains undefanged '://' — should be '[://]'", "protocol not defanged — 'http' should be 'hxxp'"]),
    ])
    def test_verify_defang_strictness(self, input_str, should_be_valid, expected_issues):
        is_valid, issues = mod.verify_defang(input_str)
        assert is_valid == should_be_valid
        for expected in expected_issues:
            assert expected in issues

# ── 2. IP Metadata & Validation ──────────────────────────────────────────────

class TestIPMetadata:
    @pytest.mark.parametrize("ip, expected_tag", [
        ("192.168.1.1", "PRIVATE / INTERNAL IP"),
        ("10.5.5.5[:]8080", "PRIVATE / INTERNAL IP"), # tests stripping port/defanged
        ("127.0.0.1", "LOOPBACK / LOCALHOST IP"),
        ("8.8.8.8", "PUBLIC / ROUTABLE IP"),
        ("224.0.0.1", "MULTICAST IP"),
        ("240.0.0.1", "RESERVED IP"),
        ("256.256.256.256", None), # Invalid IP
        ("not_an_ip.com", None)
    ])
    def test_ip_metadata_classification(self, ip, expected_tag):
        tags = mod.get_ip_metadata(ip)
        if expected_tag:
            assert expected_tag in tags
        else:
            assert tags == []

# ── 3. Chained Decoding & Cyclic Prevention ──────────────────────────────────

class TestChainedDecoding:
    def test_deep_decoding_chain(self):
        # Target: "powershell -EncodedCommand"
        # Chain: plain -> ROT13 -> URL-encoded -> Base64
        step1 = "powershell -EncodedCommand"
        step2 = codecs.encode(step1, "rot_13")
        step3 = quote(step2)
        step4 = base64.b64encode(step3.encode()).decode()
        
        result, label, layers = mod.detect_and_decode(step4)
        
        assert result == step1
        assert "Base64" in label
        assert "URL-encoded" in label
        assert "ROT13" in label
        assert len(layers) == 3

    def test_cycle_prevention(self):
        # A plain string should just return itself without looping infinitely
        result, label, layers = mod.detect_and_decode("just a normal string")
        assert result == "just a normal string"
        assert label == "plain"
        assert layers == []

    def test_invalid_base64_graceful_fail(self):
        # A string that looks like Base64 but fails decoding gracefully
        # FangVault catches exceptions and appends them to layers
        malformed = "aGVsbG8" + "!" * 10 
        result, label, layers = mod.detect_and_decode(malformed)
        assert "plain" in label or "error" in str(layers)

# ── 4. High-Fidelity Encoding Detections ─────────────────────────────────────

class TestEncodingDetection:
    @pytest.mark.parametrize("payload, expected_detect", [
        ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.sig", "JWT"),
        ("aGVsbG8gd29ybGQ=", "Base64"),
        ("aGVsbG8lM0Q=", "Base64"), # URL-encoded padding test
        ("aGVsbG8td29ybGQ_cA==", "Base64url"), # URL safe chars
        ("MZXW6YTBOI======", "Base32"),
        ("48656c6c6f", "Base16/Hex"),
        ("0x48656c6c6f", "Base16/Hex"),
        ("%3Cscript%3E", "URL-encoded"),
        ("&#60;script&#62;", "HTML entity"),
        ("\\u003cscript\\u003e", "Unicode escape"),
        ("\\U0001F600", "Unicode escape"), # Emoji unicode
        (codecs.encode("powershell.exe -bypass", "rot_13"), "ROT13"),
        ("just some plain text", "plain")
    ])
    def test_all_detectors(self, payload, expected_detect):
        assert mod._detect(payload) == expected_detect

    def test_base64_printable_heuristic_binary_rejection(self):
        # Generates random binary noise, encodes to b64. Should be rejected.
        binary_noise = bytes([x % 256 for x in range(100)])
        b64 = base64.b64encode(binary_noise).decode()
        assert mod.is_base64(b64) is False

    def test_short_rot13_rejection(self):
        # ROT13 requires security keywords. Short random words shouldn't trigger it.
        encoded = codecs.encode("apple", "rot_13")
        assert mod.is_rot13(encoded) is False

# ── 5. Full URL IOC Parsing & Traversal ──────────────────────────────────────

class TestFullUrlParsing:
    def test_massive_obfuscated_url(self):
        # URL with: IDN (Punycode), Private IP, Path Traversal, Dangerous File, Chained Query Param
        b64_payload = base64.b64encode(b"malicious_command").decode()
        url = f"https://xn--bcher-kva.com/../../windows/system32/cmd.exe?exec={b64_payload}"
        
        res = mod.decode_url_full(url)
        
        # Check Punycode
        assert "__idn_warning__" in res
        assert res["__idn_warning__"]["decoded"] == "bücher.com"
        
        # Check Traversal
        assert "traversal_flags" in res["path"]
        assert "directory traversal (../)" in res["path"]["traversal_flags"]
        
        # Check File Intent
        assert "file_intent" in res["path"]
        assert "DANGEROUS FILE" in res["path"]["file_intent"]
        
        # Check Query Decoding
        assert "query_params" in res
        assert res["query_params"]["param 'exec'"]["decoded"] == "malicious_command"
        assert res["query_params"]["param 'exec'"]["encoding"] == "Base64"

    @pytest.mark.parametrize("path, expected_flags", [
        ("/normal/path/here.html", []),
        ("/../etc/shadow", ["directory traversal (../)"]),
        ("/api%2F..%2Fsys", ["URL-encoded slash (%2F)"]),
        ("/var/www%252Fhtml", ["double-encoded slash (%252F)"]),
        ("/image.png%00.php", ["null byte (%00)"]),
        ("..%c0%af..%c0%af", ["encoded traversal sequence"]),
    ])
    def test_path_traversal_engine(self, path, expected_flags):
        flags = mod.check_path_traversal(path)
        for expected in expected_flags:
            assert expected in flags

    @pytest.mark.parametrize("path, expected_intent_keyword", [
        ("payload.EXE", "DANGEROUS"), # Case insensitivity test
        ("script.ps1", "DANGEROUS"),
        ("macro.xlsm", "DANGEROUS"),
        ("archive.7z", "DANGEROUS"),
        ("photo.PNG", "IMAGE"),
        ("icon.ico", "IMAGE"),
        ("index.html", None),
        ("unknown_ext.xyz", None)
    ])
    def test_file_intent_engine(self, path, expected_intent_keyword):
        intent = mod.check_file_intent(path)
        if expected_intent_keyword:
            assert expected_intent_keyword in intent
        else:
            assert intent is None

# ── 6. JWT Specifics ─────────────────────────────────────────────────────────

class TestJWTEdgeCases:
    def test_malformed_jwt_graceful_handling(self):
        # Valid structure, but completely invalid base64 inside
        malformed_jwt = "header.payload.signature" 
        result = mod.decode_jwt(malformed_jwt)
        # It shouldn't crash, it should just return the raw strings if it can't decode
        assert result["header"] == "header"
        assert result["payload"] == "payload"
        assert result["signature"] == "signature"

    def test_unsecured_jwt(self):
        # JWTs can legitimately have no signature
        unsecured_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        assert mod.is_jwt(unsecured_jwt) is True
        data = mod.decode_jwt(unsecured_jwt)
        assert data["header"]["alg"] == "none"
        assert data["payload"]["sub"] == "1234567890"
        assert data["signature"] == ""