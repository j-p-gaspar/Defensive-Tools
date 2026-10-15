#!/usr/bin/env bash
# Interactive launcher for the socgear toolkit. For scripting use the CLI directly:
#   python -m socgear <fangvault|ip|logon|ioc|time|hash|header> [args]

cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

PY=$(command -v python3 || command -v python || command -v py)
if [ -z "$PY" ]; then
    echo "error: Python 3 not found" >&2
    exit 2
fi

if [ -t 1 ] && [ -z "$NO_COLOR" ]; then
    CYAN=$'\033[0;36m'; GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; RESET=$'\033[0m'
else
    CYAN=; GREEN=; RED=; YELLOW=; RESET=
fi

show_menu() {
    echo "${CYAN}SOC ANALYST TOOLKIT${RESET}"
    echo "${CYAN}---------------------------------------------${RESET}"
    echo " ${GREEN}1)${RESET} FangVault  - defang / refang / decode (interactive)"
    echo " ${GREEN}2)${RESET} IP parser  - extract IPs from a file"
    echo " ${GREEN}3)${RESET} LogonLens  - decode Windows event/status codes (interactive)"
    echo " ${GREEN}4)${RESET} IOCX       - extract IOCs from a file"
    echo " ${GREEN}5)${RESET} Timestamps - convert epoch / FILETIME / WebKit"
    echo " ${GREEN}6)${RESET} Hash files - MD5/SHA1/SHA256"
    echo " ${GREEN}7)${RESET} Email headers - parse a header file"
    echo " ${GREEN}8)${RESET} Exit"
}

ask_file() {
    read -r -p "File path: " f
    [ -n "$f" ] && printf '%s\n' "$f"
}

while true; do
    show_menu
    read -r -p "Select an option [1-8]: " choice
    case $choice in
        1) "$PY" -m socgear fangvault -i ;;
        2) f=$(ask_file) && "$PY" -m socgear ip -f "$f" ;;
        3) "$PY" -m socgear logon -i ;;
        4) f=$(ask_file) && "$PY" -m socgear ioc -f "$f" ;;
        5) read -r -p "Timestamp(s): " ts; "$PY" -m socgear time $ts ;;
        6) f=$(ask_file) && "$PY" -m socgear hash "$f" ;;
        7) f=$(ask_file) && "$PY" -m socgear header -f "$f" ;;
        8) exit 0 ;;
        *) echo "${RED}Invalid option.${RESET}" ;;
    esac
    echo
    read -r -p "${YELLOW}Press Enter to return to the menu...${RESET}" _
done
