#!/bin/bash
# Search decompiled code for security-relevant patterns
#
# Usage: ./search-code.sh <pattern> [app-name]
#        ./search-code.sh --preset <preset-name> [app-name]
#
# Presets:
#   secrets   - API keys, passwords, tokens
#   network   - HTTP clients, URLs, endpoints
#   crypto    - Encryption, hashing, certificates
#   storage   - SharedPreferences, databases, files
#   auth      - Login, OAuth, JWT, session handling
#
# Examples:
#   ./search-code.sh "api.example.com"
#   ./search-code.sh --preset secrets
#   ./search-code.sh --preset network com.example.app

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Preset patterns (avoiding associative arrays for macOS compatibility)
get_preset_pattern() {
    case "$1" in
        secrets)
            echo '(api[_-]?key|apikey|secret[_-]?key|password|token|credential|auth[_-]?key|private[_-]?key).*='
            ;;
        network)
            echo '(HttpURLConnection|OkHttpClient|Retrofit|Volley|WebView|URL\(|HttpClient)'
            ;;
        crypto)
            echo '(Cipher|MessageDigest|SecretKey|KeyStore|X509|SSLContext|TrustManager|Mac\.getInstance)'
            ;;
        storage)
            echo '(SharedPreferences|SQLiteDatabase|getFilesDir|getCacheDir|Room|ContentProvider|openFileOutput)'
            ;;
        auth)
            echo '(login|authenticate|oauth|jwt|session|bearer|authorization|signIn|signOut)'
            ;;
        *)
            echo ""
            ;;
    esac
}

show_usage() {
    echo "Search decompiled code for security-relevant patterns"
    echo ""
    echo "Usage:"
    echo "  ./search-code.sh <pattern> [app-name]"
    echo "  ./search-code.sh --preset <preset-name> [app-name]"
    echo "  ./search-code.sh --list-presets"
    echo "  ./search-code.sh --help"
    echo ""
    echo "Presets:"
    echo "  secrets   - API keys, passwords, tokens"
    echo "  network   - HTTP clients, URLs, endpoints"
    echo "  crypto    - Encryption, hashing, certificates"
    echo "  storage   - SharedPreferences, databases, files"
    echo "  auth      - Login, OAuth, JWT, session handling"
    echo ""
    echo "Examples:"
    echo "  ./search-code.sh 'api.example.com'"
    echo "  ./search-code.sh --preset secrets"
    echo "  ./search-code.sh --preset network com.example.app"
    echo ""
    echo "Options:"
    echo "  --preset, -p    Use a predefined pattern"
    echo "  --list-presets  Show all preset patterns"
    echo "  --context, -C   Lines of context (default: 2)"
    echo "  --help, -h      Show this help"
}

list_presets() {
    echo "Available presets and their patterns:"
    echo ""
    echo "secrets"
    echo "  Pattern: $(get_preset_pattern secrets)"
    echo ""
    echo "network"
    echo "  Pattern: $(get_preset_pattern network)"
    echo ""
    echo "crypto"
    echo "  Pattern: $(get_preset_pattern crypto)"
    echo ""
    echo "storage"
    echo "  Pattern: $(get_preset_pattern storage)"
    echo ""
    echo "auth"
    echo "  Pattern: $(get_preset_pattern auth)"
    echo ""
}

find_sources_dir() {
    local app_name="$1"

    if [ -n "$app_name" ]; then
        # Look for specific app
        local dir="$SCRIPT_DIR/decompiled/${app_name}/jadx/sources"
        if [ -d "$dir" ]; then
            echo "$dir"
            return 0
        fi
        # Try without version suffix
        dir=$(find "$SCRIPT_DIR/decompiled" -maxdepth 1 -type d -name "${app_name}*" 2>/dev/null | head -1)
        if [ -n "$dir" ] && [ -d "$dir/jadx/sources" ]; then
            echo "$dir/jadx/sources"
            return 0
        fi
        echo "ERROR: No decompiled sources found for: $app_name" >&2
        return 1
    else
        # Find most recent decompiled sources
        local most_recent=$(ls -td "$SCRIPT_DIR/decompiled"/*/jadx/sources 2>/dev/null | head -1)
        if [ -n "$most_recent" ] && [ -d "$most_recent" ]; then
            echo "$most_recent"
            return 0
        fi
        echo "ERROR: No decompiled sources found in decompiled/" >&2
        echo "Run ./analyze-apk.sh or ./decompile-apk.sh first" >&2
        return 1
    fi
}

search_pattern() {
    local pattern="$1"
    local sources_dir="$2"
    local context="$3"

    echo "=== Search Results ==="
    echo ""
    echo "Pattern: $pattern"
    echo "Source:  $sources_dir"
    echo ""

    # Run grep with context
    local results
    results=$(grep -rniE --include="*.java" -C "$context" "$pattern" "$sources_dir" 2>/dev/null || true)

    if [ -n "$results" ]; then
        # Count matches
        local match_count=$(grep -rniE --include="*.java" -l "$pattern" "$sources_dir" 2>/dev/null | wc -l | tr -d ' ')
        local line_count=$(grep -rniE --include="*.java" "$pattern" "$sources_dir" 2>/dev/null | wc -l | tr -d ' ')

        echo "Found $line_count matches in $match_count files"
        echo ""

        # Display results with file:line references (limit output)
        echo "$results" | head -200

        if [ "$line_count" -gt 50 ]; then
            echo ""
            echo "... showing first 200 lines"
            echo "Refine your search or pipe to less: ./search-code.sh '$pattern' | less"
        fi
    else
        echo "No matches found"
    fi

    echo ""
}

# Main execution
main() {
    local pattern=""
    local preset=""
    local app_name=""
    local context=2

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --preset|-p)
                preset="$2"
                shift 2
                ;;
            --list-presets)
                list_presets
                exit 0
                ;;
            --context|-C)
                context="$2"
                shift 2
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            -*)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                if [ -z "$pattern" ] && [ -z "$preset" ]; then
                    pattern="$1"
                else
                    app_name="$1"
                fi
                shift
                ;;
        esac
    done

    # Determine pattern to use
    if [ -n "$preset" ]; then
        pattern=$(get_preset_pattern "$preset")
        if [ -z "$pattern" ]; then
            echo "ERROR: Unknown preset: $preset"
            echo ""
            echo "Available presets: secrets, network, crypto, storage, auth"
            exit 1
        fi
        echo "Using preset: $preset"
    elif [ -z "$pattern" ]; then
        show_usage
        exit 1
    fi

    # Find sources directory
    local sources_dir
    sources_dir=$(find_sources_dir "$app_name") || exit 1

    # Run search
    search_pattern "$pattern" "$sources_dir" "$context"
}

main "$@"
