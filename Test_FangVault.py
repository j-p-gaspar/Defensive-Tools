import unittest
import json
import base64
import codecs
import importlib.util

# ── Load module ───────────────────────────────────────────────────────────────
# Place this file in the same folder as FangVault.py and run:
#   pytest Test_FangVault.py -v
spec = importlib.util.spec_from_file_location("defang", "FangVault.py")
mod  = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


# ── Issue #1 — Detection Order: Base64 with %3D padding ──────────────────────

class TestIssue1_DetectionOrder(unittest.TestCase):

    def test_base64_with_encoded_padding(self):
        self.assertEqual(mod._detect("aGVsbG8%3D"), "Base64")

    def test_base64_with_lowercase_encoded_padding(self):
        self.assertEqual(mod._detect("aGVsbG8%3d"), "Base64")

    def test_real_url_encoding_still_detected(self):
        self.assertEqual(mod._detect("%41%42%43"), "URL-encoded")

    def test_mixed_url_encoding_not_base64(self):
        self.assertEqual(mod._detect("hello%20world"), "URL-encoded")

    def test_base64_decoded_correctly_via_chain(self):
        result, label, _ = mod.detect_and_decode("aGVsbG8%3D")
        self.assertEqual(result, "hello")
        self.assertIn("Base64", label)


# ── Issue #2 — ROT13 detection ────────────────────────────────────────────────

class TestIssue2_ROT13(unittest.TestCase):

    def test_rot13_powershell_url(self):
        encoded = codecs.encode("https://malware.com/payload.ps1", "rot_13")
        self.assertEqual(mod._detect(encoded), "ROT13")

    def test_rot13_exe_dropper(self):
        encoded = codecs.encode("cmd.exe /c download.bat", "rot_13")
        self.assertEqual(mod._detect(encoded), "ROT13")

    def test_rot13_decodes_correctly(self):
        encoded = codecs.encode("powershell -EncodedCommand", "rot_13")
        result, label, layers = mod.detect_and_decode(encoded)
        self.assertEqual(result, "powershell -EncodedCommand")
        self.assertIn("ROT13", label)

    def test_plain_english_not_rot13(self):
        self.assertNotEqual(mod._detect("the quick brown fox"), "ROT13")

    def test_short_string_not_rot13(self):
        self.assertNotEqual(mod._detect("abc"), "ROT13")


# ── Issue #3 — Base64 printable-output heuristic ─────────────────────────────

class TestIssue3_Base64Printable(unittest.TestCase):

    def test_printable_base64_accepted(self):
        self.assertTrue(mod.is_base64("aGVsbG8gd29ybGQ="))

    def test_binary_base64_rejected(self):
        raw = bytes(range(0, 64))
        b64 = base64.b64encode(raw).decode()
        self.assertFalse(mod.is_base64(b64))

    def test_short_base64_rejected(self):
        self.assertFalse(mod.is_base64("dA=="))

    def test_url_payload_base64_accepted(self):
        payload = base64.b64encode(b"https://evil.com/shell.ps1").decode()
        self.assertTrue(mod.is_base64(payload))

    def test_base64url_binary_rejected(self):
        raw = bytes(range(128, 192))
        b64u = base64.urlsafe_b64encode(raw).decode()
        self.assertFalse(mod.is_base64url(b64u))


# ── Issue #4 — Unicode escape decoder ────────────────────────────────────────

class TestIssue4_UnicodeEscape(unittest.TestCase):

    def test_basic_ascii_unicode_escape(self):
        result = mod._run_decoder("Unicode escape", "\\u0041\\u0042\\u0043")
        self.assertEqual(result, "ABC")

    def test_non_ascii_unicode_escape(self):
        result = mod._run_decoder("Unicode escape", "\\u00e9")
        self.assertEqual(result, "é")

    def test_mixed_unicode_and_ascii(self):
        result = mod._run_decoder("Unicode escape", "hello\\u0021")
        self.assertEqual(result, "hello!")

    def test_uppercase_U_escape(self):
        result = mod._run_decoder("Unicode escape", "\\U0001F600")
        self.assertEqual(result, "😀")

    def test_detect_unicode_escape(self):
        s = "\\u0068\\u0065\\u006C\\u006C\\u006F"
        self.assertEqual(mod._detect(s), "Unicode escape")

    def test_unicode_escape_full_decode(self):
        s = "\\u0068\\u0065\\u006C\\u006C\\u006F"
        result, label, _ = mod.detect_and_decode(s)
        self.assertEqual(result, "hello")


# ── Issue #5 — JWT detection ──────────────────────────────────────────────────

class TestIssue5_JWT(unittest.TestCase):

    SAMPLE_JWT = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    def test_jwt_detected(self):
        self.assertEqual(mod._detect(self.SAMPLE_JWT), "JWT")

    def test_jwt_not_base64url(self):
        self.assertNotEqual(mod._detect(self.SAMPLE_JWT), "Base64url")

    def test_jwt_decode_header(self):
        data = mod.decode_jwt(self.SAMPLE_JWT)
        self.assertIn("header", data)
        self.assertEqual(data["header"].get("alg"), "HS256")
        self.assertEqual(data["header"].get("typ"), "JWT")

    def test_jwt_decode_payload(self):
        data = mod.decode_jwt(self.SAMPLE_JWT)
        self.assertIn("payload", data)
        self.assertEqual(data["payload"].get("sub"), "1234567890")

    def test_jwt_decode_has_signature(self):
        data = mod.decode_jwt(self.SAMPLE_JWT)
        self.assertIn("signature", data)
        self.assertTrue(len(data["signature"]) > 0)

    def test_short_dotted_string_not_jwt(self):
        result = mod._detect("hello.world.foo")
        self.assertNotEqual(result, "JWT")

    def test_jwt_is_terminal_in_chain(self):
        _, _, layers = mod.detect_and_decode(self.SAMPLE_JWT)
        self.assertEqual(len(layers), 1)
        self.assertEqual(layers[0]["encoding"], "JWT")


# ── Issue #6 — Inline decode <url> ───────────────────────────────────────────

class TestIssue6_InlineDecode(unittest.TestCase):

    def test_function_exists(self):
        self.assertTrue(hasattr(mod, "print_inline_decode"))
        self.assertTrue(callable(mod.print_inline_decode))

    def test_detect_and_decode_on_arbitrary_input(self):
        payload = base64.b64encode(b"http://evil.com").decode()
        result, label, layers = mod.detect_and_decode(payload)
        self.assertEqual(result, "http://evil.com")
        self.assertIn("Base64", label)

    def test_decode_url_full_on_plain_url(self):
        result = mod.decode_url_full("https://google.com/search?q=test")
        self.assertIn("path", result)


# ── Issue #7 — Punycode / IDN decoding ───────────────────────────────────────

class TestIssue7_Punycode(unittest.TestCase):

    def test_punycode_hostname_decoded(self):
        result = mod.decode_punycode("xn--googl-hwe.com")
        self.assertIsNotNone(result)

    def test_non_punycode_returns_none(self):
        result = mod.decode_punycode("google.com")
        self.assertIsNone(result)

    def test_idn_warning_in_full_url_decode(self):
        result = mod.decode_url_full("https://xn--googl-hwe.com/path")
        self.assertIn("__idn_warning__", result)

    def test_idn_warning_note_text(self):
        result = mod.decode_url_full("https://xn--googl-hwe.com/path")
        note = result["__idn_warning__"]["note"]
        self.assertIn("homograph", note.lower())

    def test_normal_domain_no_idn_warning(self):
        result = mod.decode_url_full("https://google.com/search?q=test")
        self.assertNotIn("__idn_warning__", result)

    def test_idn_original_preserved(self):
        result = mod.decode_url_full("https://xn--googl-hwe.com/path")
        self.assertEqual(result["__idn_warning__"]["original"], "xn--googl-hwe.com")


# ── Issue #8 — Path traversal / IOC flag detection ───────────────────────────

class TestIssue8_PathTraversal(unittest.TestCase):

    def test_dot_dot_slash_detected(self):
        flags = mod.check_path_traversal("/admin/../etc/passwd")
        self.assertIn("directory traversal (../)", flags)

    def test_url_encoded_slash_detected(self):
        flags = mod.check_path_traversal("/admin%2Fetc%2Fpasswd")
        self.assertIn("URL-encoded slash (%2F)", flags)

    def test_double_encoded_slash_detected(self):
        flags = mod.check_path_traversal("/admin%252Fetc")
        self.assertIn("double-encoded slash (%252F)", flags)

    def test_null_byte_detected(self):
        flags = mod.check_path_traversal("/file.php%00.jpg")
        self.assertIn("null byte (%00)", flags)

    def test_clean_path_no_flags(self):
        flags = mod.check_path_traversal("/api/v1/users")
        self.assertEqual(flags, [])

    def test_traversal_flagged_in_full_url_decode(self):
        result = mod.decode_url_full("https://example.com/../etc/passwd")
        path_info = result.get("path", {})
        self.assertIn("traversal_flags", path_info)

    def test_multiple_flags_in_one_path(self):
        flags = mod.check_path_traversal("/../admin%2F..%2Fetc%00passwd")
        self.assertGreater(len(flags), 1)

    def test_encoded_slash_check(self):
        findings_encoded = mod.check_path_traversal("..%2f..%2f")
        self.assertIn("URL-encoded slash (%2F)", findings_encoded)


# ── Regression — core defang/fang must still work ────────────────────────────

class TestDefangFang(unittest.TestCase):

    def test_defang_ipv4(self):
        defanged, kind = mod.defang("192.168.1.1")
        self.assertEqual(defanged, "192[.]168[.]1[.]1")
        self.assertEqual(kind, "IP")
        
    def test_defang_ip_with_port(self):
        defanged, kind = mod.defang("192.168.1.1:8080")
        self.assertEqual(defanged, "192[.]168[.]1[.]1[:]8080")
        self.assertEqual(kind, "IP")

    def test_fang_ipv4(self):
        fanged, kind = mod.fang("192[.]168[.]1[.]1")
        self.assertEqual(fanged, "192.168.1.1")
        self.assertEqual(kind, "IP")

    def test_defang_url(self):
        defanged, kind = mod.defang("https://evil.com/payload")
        self.assertIn("hxxp", defanged)
        self.assertIn("[.]", defanged)
        self.assertEqual(kind, "URL")

    def test_fang_url(self):
        fanged, _ = mod.fang("hxxps[://]evil[.]com/payload")
        self.assertIn("https://", fanged)
        self.assertIn("evil.com", fanged)
        
    def test_fang_url_basic(self):
        fanged, kind = mod.fang("hxxp[://]malware[.]com/test[.]php")
        self.assertEqual(fanged, "http://malware.com/test.php")
        self.assertEqual(kind, "URL")

    def test_already_defanged_detection_true(self):
        self.assertTrue(mod.is_already_defanged("hxxps[://]evil[.]com"))

    def test_already_defanged_detection_false(self):
        self.assertFalse(mod.is_already_defanged("https://evil.com"))

    def test_verify_defang_valid(self):
        is_valid, issues = mod.verify_defang("hxxps[://]evil[.]com/path")
        self.assertTrue(is_valid)
        self.assertEqual(issues, [])

    def test_verify_defang_bare_dot(self):
        is_valid, issues = mod.verify_defang("hxxps[://]evil.com/path")
        self.assertFalse(is_valid)
        self.assertTrue(any("." in i for i in issues))

    def test_verify_defang_bare_protocol(self):
        is_valid, issues = mod.verify_defang("https://evil[.]com/path")
        self.assertFalse(is_valid)

    def test_undo_removes_last_entry(self):
        history_urls = []
        history_log  = []
        defanged, _ = mod.defang("https://evil.com")
        history_urls.append(defanged)
        history_log.append(("URL", defanged))
        last_type, last_val = history_log.pop()
        history_urls.remove(last_val)
        self.assertEqual(history_urls, [])


# ── Multi-layer decoding chain ────────────────────────────────────────────────

class TestDecodingChain(unittest.TestCase):

    def test_url_encoded_base64(self):
        result, label, layers = mod.detect_and_decode("aGVsbG8%3D")
        self.assertEqual(result, "hello")

    def test_double_base64(self):
        inner = base64.b64encode(b"malware").decode()
        outer = base64.b64encode(inner.encode()).decode()
        result, label, layers = mod.detect_and_decode(outer)
        self.assertEqual(result, "malware")
        self.assertEqual(len(layers), 2)

    def test_plain_string_no_layers(self):
        result, label, layers = mod.detect_and_decode("hello world")
        self.assertEqual(label, "plain")
        self.assertEqual(layers, [])

    def test_html_entity_decoded(self):
        result, label, _ = mod.detect_and_decode("&lt;script&gt;")
        self.assertEqual(result, "<script>")

    def test_base32_decoded(self):
        encoded = base64.b32encode(b"http://evil.com").decode()
        result, label, _ = mod.detect_and_decode(encoded)
        self.assertEqual(result, "http://evil.com")
        self.assertIn("Base32", label)

    def test_hex_decoded(self):
        encoded = b"evil.com".hex()
        result, label, _ = mod.detect_and_decode(encoded)
        self.assertEqual(result, "evil.com")
        self.assertIn("Base16", label)

    def test_cycle_prevention(self):
        result, label, layers = mod.detect_and_decode("plain text here")
        self.assertEqual(label, "plain")


# ── New Tests: IP Metadata, File Intent, & Full Decode Integration ───────────

class TestIPNetworkContext(unittest.TestCase):

    def test_get_ip_metadata_private(self):
        tags = mod.get_ip_metadata("192[.]168[.]1[.]50")
        self.assertIn("PRIVATE / INTERNAL IP", tags)

    def test_get_ip_metadata_public(self):
        # Testing with ports and defanged syntax to ensure stripping works
        tags = mod.get_ip_metadata("8[.]8[.]8[.]8[:]443")
        self.assertIn("PUBLIC / ROUTABLE IP", tags)

    def test_get_ip_metadata_loopback(self):
        tags = mod.get_ip_metadata("127.0.0.1")
        self.assertIn("LOOPBACK / LOCALHOST IP", tags)

    def test_get_ip_metadata_invalid(self):
        tags = mod.get_ip_metadata("not-an-ip.com")
        self.assertEqual(tags, [])


class TestFileDownloadIntent(unittest.TestCase):

    def test_check_file_intent_dangerous(self):
        self.assertIn("DANGEROUS FILE", mod.check_file_intent("/payload.exe"))
        self.assertIn("DANGEROUS FILE", mod.check_file_intent("/scripts/run.ps1"))
        self.assertIn("DANGEROUS FILE", mod.check_file_intent("/archive.zip"))

    def test_check_file_intent_image(self):
        self.assertIn("IMAGE FILE", mod.check_file_intent("/logo.png"))
        self.assertIn("IMAGE FILE", mod.check_file_intent("/background.JPG"))

    def test_check_file_intent_safe_or_unknown(self):
        self.assertIsNone(mod.check_file_intent("/index.html"))
        self.assertIsNone(mod.check_file_intent("/api/v1/users"))


class TestFullURLDecodingIntegration(unittest.TestCase):

    def test_decode_url_full_integration(self):
        url = "http://10.0.0.5/downloads/malware.exe?encoded=YWRtaW4="
        results = mod.decode_url_full(url)
        
        # Check if network warning was triggered for the IP
        self.assertIn("__network_warning__", results)
        self.assertIn("PRIVATE / INTERNAL IP", results["__network_warning__"])
        
        # Check if the path correctly identified the dangerous file
        self.assertIn("path", results)
        self.assertIn("file_intent", results["path"])
        self.assertIn("DANGEROUS FILE: .exe", results["path"]["file_intent"])
        
        # Check if the query parameter was decoded from Base64
        self.assertIn("query_params", results)
        self.assertIn("param 'encoded'", results["query_params"])
        self.assertEqual(results["query_params"]["param 'encoded'"]["decoded"], "admin")


if __name__ == "__main__":
    unittest.main(verbosity=2)