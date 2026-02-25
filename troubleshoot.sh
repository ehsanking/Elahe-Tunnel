#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Running Elahe Tunnel Diagnostic Tool...${NC}"
echo "========================================================"

# 1. Check if process is running
echo -n "Checking if elahe-tunnel is running... "
if pgrep -x "elahe-tunnel" > /dev/null; then
    echo -e "${GREEN}YES (PID: $(pgrep -x elahe-tunnel))${NC}"
else
    echo -e "${RED}NO${NC}"
    echo -e "   -> Try running: ${YELLOW}elahe-tunnel run${NC}"
fi

# 2. Check Port 443
echo -n "Checking if Port 443 is listening... "
if lsof -i :443 | grep LISTEN > /dev/null; then
    echo -e "${GREEN}YES${NC}"
    PROCESS_NAME=$(lsof -i :443 | grep LISTEN | awk '{print $1}' | head -n 1)
    if [ "$PROCESS_NAME" == "elahe-tun" ] || [ "$PROCESS_NAME" == "elahe-tunnel" ]; then
        echo -e "   -> Bound to: ${GREEN}elahe-tunnel${NC}"
    else
        echo -e "   -> Bound to: ${RED}$PROCESS_NAME (Conflict!)${NC}"
        echo -e "   -> You must stop $PROCESS_NAME: ${YELLOW}systemctl stop $PROCESS_NAME${NC}"
    fi
else
    echo -e "${RED}NO${NC}"
fi

# 3. Check Firewall (UFW)
if command -v ufw > /dev/null; then
    echo -n "Checking UFW Firewall... "
    UFW_STATUS=$(ufw status | grep -i "Status: active")
    if [ -n "$UFW_STATUS" ]; then
        echo -e "${YELLOW}Active${NC}"
        if ufw status | grep 443 | grep ALLOW > /dev/null; then
            echo -e "   -> Port 443: ${GREEN}ALLOWED${NC}"
        else
            echo -e "   -> Port 443: ${RED}NOT ALLOWED${NC}"
            echo -e "   -> Fix: ${YELLOW}ufw allow 443/tcp${NC}"
        fi
    else
        echo -e "${GREEN}Inactive (OK)${NC}"
    fi
fi

# 4. Check IPTables
echo -n "Checking IPTables... "
if iptables -L INPUT -n | grep "dpt:443" | grep -E "DROP|REJECT" > /dev/null; then
    echo -e "${RED}BLOCKING RULES FOUND${NC}"
else
    echo -e "${GREEN}No blocking rules found for port 443${NC}"
fi

echo "========================================================"
echo -e "Diagnostic complete."
