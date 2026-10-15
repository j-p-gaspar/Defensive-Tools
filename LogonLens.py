import sys
import re

# --- ANSI Styling ---
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
CLEAR = "\033[H\033[J"

LOG_DATA = {
    "ERRORS": {
        # --- Authentication Status Codes ---
        "0XC0000064": "STATUS_NO_SUCH_USER - User does not exist.",
        "0XC000006A": "STATUS_WRONG_PASSWORD - Misspelled or bad password.",
        "0XC000006D": "STATUS_LOGON_FAILURE - Bad username or authentication.",
        "0XC000006E": "STATUS_ACCOUNT_RESTRICTION - Account restriction prevented login.",
        "0XC000006F": "STATUS_INVALID_LOGON_HOURS - Logon outside allowed hours.",
        "0XC0000070": "STATUS_INVALID_WORKSTATION - Unauthorized workstation.",
        "0XC0000071": "STATUS_PASSWORD_EXPIRED - Password has expired.",
        "0XC0000072": "STATUS_ACCOUNT_DISABLED - Account is currently disabled.",
        "0XC000015B": "STATUS_LOGON_TYPE_NOT_GRANTED - Logon type not granted.",
        "0XC0000193": "STATUS_ACCOUNT_EXPIRED - The user account has expired.",
        "0XC0000224": "STATUS_PASSWORD_MUST_CHANGE - Password change required.",
        "0XC0000234": "STATUS_ACCOUNT_LOCKED_OUT - Locked due to failed attempts.",
        "0XC0000380": "STATUS_SMARTCARD_LOGON_REQUIRED - Smartcard required.",
        "0XC0000413": "STATUS_AUTHENTICATION_FIREWALL_FAILED - Blocked by Authentication Firewall.",
        "0X5": "ERROR_ACCESS_DENIED - Access is denied.",
        "0X0": "SUCCESS - Operation completed successfully.",
        
        # --- Kerberos Specific Errors (Sub-codes) ---
        "0X6": "KDC_ERR_CLIENT_REVOKED - Clients credentials have been revoked.",
        "0XC": "KDC_ERR_POLICY - KDC policy rejects request.",
        "0X12": "KDC_ERR_CLIENT_NOT_TRUSTED - Client not trusted by KDC.",
        "0X17": "KDC_ERR_PREAUTH_FAILED - Bad password or time drift.",
        "0X18": "KDC_ERR_PREAUTH_REQUIRED - Pre-authentication required.",
        "0X25": "KRB_AP_ERR_SKEW - Clock skew too great (Time out of sync).",
        "0X2F": "KRB_AP_ERR_ILL_CRC - Integrity check on decrypted field failed."
    },
    "EVENTS": {
        # --- Logon/Logoff ---
        "4624": "Successful Logon",
        "4625": "Failed Logon",
        "4634": "Account Logoff",
        "4647": "User initiated logoff",
        "4648": "Logon using explicit credentials (RunAs)",
        "4672": "Special privileges assigned to new logon (Admin rights)",
        
        # --- Account Management ---
        "4720": "User account created",
        "4722": "User account enabled",
        "4723": "Attempt to change an account's password",
        "4724": "Attempt to reset an account's password",
        "4725": "User account disabled",
        "4726": "User account deleted",
        "4740": "User account locked out",
        
        # --- Kerberos/NTLM Authentication ---
        "4768": "Kerberos TGT requested (Authentication Ticket)",
        "4769": "Kerberos Service Ticket requested (TGS)",
        "4771": "Kerberos pre-authentication failed (Often bad password)",
        "4776": "NTLM Credential validation (Domain Controller checked creds)",
        
        # --- System & Group Policy ---
        "1102": "Security audit log was cleared (CRITICAL ALERT)",
        "4719": "System audit policy was changed",
        "4732": "A member was added to a security-enabled local group",
        "4733": "A member was removed from a security-enabled local group"
    }
}

def extract_valid_patterns(text):
    hex_pattern = r"(?:0X)?[0-9A-F]{1,8}"
    event_pattern = r"\b\d{4}\b"
    found_hex = re.findall(hex_pattern, text.upper())
    found_events = re.findall(event_pattern, text)
    results = []
    for h in found_hex:
        if len(h) > 4 or h.startswith("0X"):
            results.append(h if h.startswith("0X") else f"0X{h}")
    return list(set(results + found_events))

def print_ui():
    """Prints a perfectly aligned box TUI."""
    # The box is exactly 60 characters wide
    print(f"{BLUE}╔══════════════════════════════════════════════════════════╗")
    print(f"║ {BOLD}{CYAN}LOGON-LENS v2.3{RESET}{BLUE}                                          ║")
    print(f"╠══════════════════════════════════════════════════════════╣")
    print(f"║ {BOLD}COMMANDS:{RESET} {YELLOW}search [term]{RESET} | {YELLOW}clear{RESET} | {RED}exit{RESET}                   {BLUE}║")
    print(f"║ {BOLD}PASTE LOGS/CODES BELOW:{RESET}                                  {BLUE}║")
    print(f"╚══════════════════════════════════════════════════════════╝{RESET}")

def main():
    history_events = {}
    history_errors = {}

    print(CLEAR, end="")

    while True:
        print_ui()
        
        if history_events or history_errors:
            print(f"\n{BOLD}{MAGENTA}─── SESSION ANALYSIS ───{RESET}")
            if history_events:
                print(f"{CYAN}[ EVENTS ]{RESET}")
                for eid, desc in sorted(history_events.items()):
                    print(f"  {BOLD}{eid}{RESET} - {desc}")
            if history_errors:
                print(f"\n{RED}[ ERRORS ]{RESET}")
                for err, desc in sorted(history_errors.items()):
                    print(f"  {BOLD}{err}{RESET} - {desc}")
            print(f"{MAGENTA}──────────────────────────────{RESET}\n")

        try:
            prompt = f"{BOLD}{GREEN}soc-analyst@tools{RESET}:{BLUE}~$ {RESET}"
            raw_input = input(prompt).strip()

            if not raw_input:
                print(CLEAR, end="")
                continue

            cmd_lower = raw_input.lower()
            
            if cmd_lower in ['exit', 'quit']:
                print(f"{RED}Shutting down...{RESET}")
                break
            
            if cmd_lower == 'clear':
                history_events.clear()
                history_errors.clear()
                print(CLEAR, end="")
                continue

            if cmd_lower.startswith("search "):
                term = raw_input[7:].upper()
                print(f"\n{YELLOW}Searching...{RESET}")
                matches = 0
                for cat, data in LOG_DATA.items():
                    for k, v in data.items():
                        if term in k or term in v.upper():
                            print(f" {GREEN}[{cat}]{RESET} {k}: {v}")
                            matches += 1
                if matches == 0:
                    print(f"\n{RED}<404> No Results Found{RESET}")
                input(f"\n{BLUE}Press Enter...{RESET}")
                print(CLEAR, end="")
                continue

            discovered = extract_valid_patterns(raw_input)
            for item in discovered:
                if item in LOG_DATA["EVENTS"]:
                    history_events[item] = LOG_DATA["EVENTS"][item]
                elif item in LOG_DATA["ERRORS"]:
                    history_errors[item] = LOG_DATA["ERRORS"][item]
            
            print(CLEAR, end="")

        except KeyboardInterrupt:
            print(f"\n{RED}Exiting...{RESET}")
            break

if __name__ == "__main__":
    main()