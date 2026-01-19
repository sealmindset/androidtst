#!/bin/bash
# Unified APK analysis - decompile and scan for security issues
#
# Usage: ./analyze-apk.sh [path/to/app.apk]
#        (defaults to most recent APK in apks/ directory)
#
# Prerequisites:
#   - jadx installed: brew install jadx
#   - apktool installed: brew install apktool

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check for required tools
check_tools() {
    local missing=()
    command -v jadx &> /dev/null || missing+=("jadx")
    command -v apktool &> /dev/null || missing+=("apktool")

    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}ERROR: Missing required tools: ${missing[*]}${NC}"
        echo ""
        echo "Install with Homebrew:"
        for tool in "${missing[@]}"; do
            echo "  brew install $tool"
        done
        exit 1
    fi
}

# Get APK path
get_apk_path() {
    if [ -n "$1" ]; then
        APK_PATH="$1"
    else
        # Find most recent APK in apks/ directory
        APK_PATH=$(ls -t "$SCRIPT_DIR/apks"/*.apk 2>/dev/null | head -1)
        if [ -z "$APK_PATH" ]; then
            echo -e "${RED}ERROR: No APK specified and none found in apks/${NC}"
            echo ""
            echo "Usage: ./analyze-apk.sh [path/to/app.apk]"
            echo ""
            echo "Extract an APK first: ./extract-apk.sh <package-name>"
            exit 1
        fi
    fi

    # Validate APK exists
    if [ ! -f "$APK_PATH" ]; then
        echo -e "${RED}ERROR: APK not found: $APK_PATH${NC}"
        exit 1
    fi
}

# Run decompilation tools
run_decompilation() {
    echo -e "${BLUE}[1/4] Decompiling to Java source (jadx)...${NC}"
    "$SCRIPT_DIR/decompile-apk.sh" "$APK_PATH" > /dev/null 2>&1
    echo -e "      ${GREEN}Done${NC}"

    echo -e "${BLUE}[2/4] Decoding resources (apktool)...${NC}"
    "$SCRIPT_DIR/decode-apk.sh" "$APK_PATH" > /dev/null 2>&1
    echo -e "      ${GREEN}Done${NC}"
}

# Security scan functions
scan_permissions() {
    local manifest="$OUTPUT_DIR/apktool/AndroidManifest.xml"
    if [ -f "$manifest" ]; then
        echo -e "\n${YELLOW}=== Permissions ===${NC}"
        local perms=$(grep -oP 'android:name="\K[^"]+' "$manifest" 2>/dev/null | grep "permission" || true)
        if [ -n "$perms" ]; then
            echo "$perms" | while read -r perm; do
                # Highlight dangerous permissions
                if echo "$perm" | grep -qE "(CAMERA|CONTACTS|LOCATION|MICROPHONE|PHONE|SMS|STORAGE|CALENDAR)"; then
                    echo -e "  ${RED}$perm${NC}"
                else
                    echo "  $perm"
                fi
            done
        else
            echo "  No permissions found"
        fi
        local count=$(grep -c "uses-permission" "$manifest" 2>/dev/null || echo "0")
        echo -e "  ${BLUE}Total: $count permissions${NC}"
    fi
}

scan_exported_components() {
    local manifest="$OUTPUT_DIR/apktool/AndroidManifest.xml"
    if [ -f "$manifest" ]; then
        echo -e "\n${YELLOW}=== Exported Components (Attack Surface) ===${NC}"
        local exported=$(grep -B5 'exported="true"' "$manifest" 2>/dev/null | grep -oP 'android:name="\K[^"]+' || true)
        if [ -n "$exported" ]; then
            echo "$exported" | while read -r comp; do
                echo -e "  ${RED}$comp${NC}"
            done
            local count=$(grep -c 'exported="true"' "$manifest" 2>/dev/null || echo "0")
            echo -e "  ${BLUE}Total: $count exported components${NC}"
        else
            echo "  No exported components found"
        fi
    fi
}

scan_network_config() {
    local manifest="$OUTPUT_DIR/apktool/AndroidManifest.xml"
    local nsc="$OUTPUT_DIR/apktool/res/xml/network_security_config.xml"

    echo -e "\n${YELLOW}=== Network Configuration ===${NC}"

    # Check for cleartext traffic in manifest
    if [ -f "$manifest" ]; then
        if grep -q 'usesCleartextTraffic="true"' "$manifest" 2>/dev/null; then
            echo -e "  ${RED}WARNING: Cleartext traffic enabled in manifest${NC}"
        fi
    fi

    # Check network security config
    if [ -f "$nsc" ]; then
        echo "  Network Security Config found:"
        if grep -qi "cleartextTrafficPermitted.*true" "$nsc" 2>/dev/null; then
            echo -e "    ${RED}Cleartext traffic permitted${NC}"
        fi
        if grep -qi "trust-anchors" "$nsc" 2>/dev/null; then
            echo -e "    ${YELLOW}Custom trust anchors defined${NC}"
        fi
        echo "    Path: $nsc"
    else
        echo "  No network_security_config.xml found"
    fi
}

scan_hardcoded_secrets() {
    local sources="$OUTPUT_DIR/jadx/sources"
    if [ -d "$sources" ]; then
        echo -e "\n${YELLOW}=== Potential Hardcoded Secrets ===${NC}"
        local pattern='(api[_-]?key|apikey|secret[_-]?key|password|token|credential|auth[_-]?key).*=.*["\x27][^"\x27]{8,}'
        local matches=$(grep -rEio "$pattern" "$sources" 2>/dev/null | head -20 || true)
        if [ -n "$matches" ]; then
            echo "$matches" | while read -r match; do
                # Truncate long lines
                echo -e "  ${RED}${match:0:100}...${NC}"
            done
            local count=$(grep -rEio "$pattern" "$sources" 2>/dev/null | wc -l || echo "0")
            echo -e "  ${BLUE}Total matches: $count (showing first 20)${NC}"
        else
            echo "  No obvious hardcoded secrets found"
        fi
    fi
}

scan_network_classes() {
    local sources="$OUTPUT_DIR/jadx/sources"
    if [ -d "$sources" ]; then
        echo -e "\n${YELLOW}=== Network-Related Classes ===${NC}"
        local files=$(grep -rlE "(HttpURLConnection|OkHttp|Retrofit|Volley|WebView)" "$sources" 2>/dev/null | head -10 || true)
        if [ -n "$files" ]; then
            echo "$files" | while read -r file; do
                # Show relative path from sources
                local rel=${file#$sources/}
                echo "  $rel"
            done
            local count=$(grep -rlE "(HttpURLConnection|OkHttp|Retrofit|Volley|WebView)" "$sources" 2>/dev/null | wc -l || echo "0")
            echo -e "  ${BLUE}Total: $count files with network code${NC}"
        else
            echo "  No network-related classes found"
        fi
    fi
}

show_next_steps() {
    echo -e "\n${GREEN}=== Next Steps ===${NC}"
    echo ""
    echo "Browse decompiled code:"
    echo "  code $OUTPUT_DIR/jadx/sources"
    echo ""
    echo "Search for patterns:"
    echo "  ./search-code.sh --preset secrets"
    echo "  ./search-code.sh --preset network"
    echo "  ./search-code.sh \"api.example.com\""
    echo ""
    echo "View manifest:"
    echo "  cat $OUTPUT_DIR/apktool/AndroidManifest.xml"
    echo ""
    echo "Find specific code:"
    echo "  grep -r \"pattern\" $OUTPUT_DIR/jadx/sources/"
}

# Main execution
main() {
    check_tools
    get_apk_path "$1"

    APK_NAME=$(basename "$APK_PATH" .apk)
    OUTPUT_DIR="$SCRIPT_DIR/decompiled/${APK_NAME}"

    echo ""
    echo -e "${GREEN}=== APK Analysis ===${NC}"
    echo ""
    echo -e "Target: ${BLUE}$APK_PATH${NC}"
    echo -e "Output: ${BLUE}$OUTPUT_DIR${NC}"
    echo ""

    run_decompilation

    echo -e "${BLUE}[3/4] Scanning for security issues...${NC}"

    scan_permissions
    scan_exported_components
    scan_network_config
    scan_hardcoded_secrets
    scan_network_classes

    echo -e "\n${BLUE}[4/4] Analysis complete${NC}"

    show_next_steps
}

main "$@"
