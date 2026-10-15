#!/bin/bash

# --- Colors for the Menu ---
CYAN='\033[0;36m'
GREEN='\033[0;32m'
MAGENTA='\033[0;35m'
YELLOW='\033[1;33m'
RESET='\033[0m'

show_menu() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║${RESET}                   ${MAGENTA}${BOLD}SOC ANALYST TOOLKIT         ${RESET}           ${CYAN}║${RESET}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${CYAN}║${RESET}  ${GREEN}1)${RESET} FangVault (Defang/Refang/Decode URLs & IPs)          ${CYAN}║${RESET}"
    echo -e "${CYAN}║${RESET}  ${GREEN}2)${RESET} IP_Parser (Extract Unique IPs from Text)             ${CYAN}║${RESET}"
    echo -e "${CYAN}║${RESET}  ${GREEN}3)${RESET} LogonLens (Analyze Windows Event & Error Codes)      ${CYAN}║${RESET}"
    echo -e "${CYAN}║${RESET}  ${GREEN}4)${RESET} Exit                                                 ${CYAN}║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${RESET}"
}

while true; do
    show_menu
    read -p "Select an option [1-4]: " choice

    case $choice in
        1)
            echo -e "\n${YELLOW}Starting FangVault...${RESET}"
            python3 FangVault.py
            ;;
        2)
            echo -e "\n${YELLOW}Starting IP_Parser...${RESET}"
            python3 IP_Parser.py
            ;;
        3)
            echo -e "\n${YELLOW}Starting LogonLens...${RESET}"
            python3 LogonLens.py
            ;;
        4)
            echo -e "${MAGENTA}Goodbye!${RESET}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option. Try again.${RESET}"
            sleep 1
            ;;
    esac
done