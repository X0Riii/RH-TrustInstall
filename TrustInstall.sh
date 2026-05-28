#!/usr/bin/env bash
#
# install-local.sh — Safe local package discovery and installation tool
#
# Discovers .rpm and .AppImage files in the current directory, analyzes
# risks, and guides the user through installation with full transparency.
#
# License: GPL3.0
#
# SHELL SECURITY CONFIGURATION:
# -e: Exit immediately if any command exits with a non-zero status.
# -u: Treat unset variables as an error.
# -o pipefail: Pipeline status is that of the last command to fail.
# -E: Ensure ERR trap is inherited by functions and subshells.
set -euEo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# GLOBALS
# ──────────────────────────────────────────────────────────────────────────────

SCRIPT_NAME="$(basename "$0")"                               # Script executable file name
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"                  # Absolute directory containing the script
START_DIR="$(pwd)"                                           # Current working directory upon starting script
TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"                     # Execution timestamp for logging/reporting

# System intelligence variables collected during pre-flight validation (Stage 0)
OS_NAME=""                                                   # Operating system name from os-release
OS_VERSION=""                                                # OS version identifier
OS_ID=""                                                     # OS ID (e.g. fedora, rhel)
PACKAGE_MANAGER=""                                           # Package manager string containing name and version details
CURRENT_USER="$(id -un)"                                     # Username running this instance
IS_ROOT=false                                                # Indicator if execution context has root privileges
DISK_SPACE_AVAIL=""                                          # Formatted string of available storage space
DISK_SPACE_WARN=false                                        # Low storage alarm indicator
HAS_DNF=false                                                # Presence flag of dnf command line utility
HAS_RPM=false                                                # Presence flag of rpm command line utility
HAS_FUSE=false                                               # Presence flag of FUSE (filesystem in userspace) layer
HAS_GPG=false                                                # Presence flag of GnuPG tool
HAS_DESKTOP=false                                            # Graphical environment detection indicator
HAS_UPDATE_DESKTOP_DB=false                                  # Presence of update-desktop-database command
DESKTOP_ENV=""                                               # Name of active Desktop Environment (e.g., Gnome)
HAS_INTERNET=false                                           # Passive connectivity check flag
HAS_FILE_CMD=false                                           # Presence flag of 'file' command utility
HAS_DU_CMD=false                                             # Presence flag of 'du' command utility
HAS_SHA256SUM=false                                          # Presence flag of 'sha256sum' command utility
HAS_MKTEMP=false                                             # Presence flag of 'mktemp' command utility
HAS_TPUT=false                                               # Presence flag of 'tput' terminal settings engine

# Color codes mapped via terminfo database (defaulting to empty for non-color/pipe environments)
C_RED=""
C_GREEN=""
C_YELLOW=""
C_BLUE=""
C_GRAY=""
C_BOLD=""
C_RESET=""

# Local package lists collected dynamically during Stage 1
declare -a RPM_FILES=()                                      # List of detected local RPM package paths
declare -a APPIMAGE_FILES=()                                 # List of detected local AppImage paths
declare -a ALL_PACKAGES=()                                   # Combined menu string descriptors
declare -a ALL_PACKAGES_TYPES=()                             # Parallel package types array ('RPM' or 'AppImage')
declare -a ALL_PACKAGES_PATHS=()                             # Parallel absolute target paths
declare -a ALL_PACKAGES_SIZES=()                             # Parallel file size strings
declare -a ALL_PACKAGES_SHA256=()                            # Parallel cryptographic checksum strings

# Cache DNF dry-run output so we only call it once (risk_analysis → install_rpm)
# Preserves consistency of information and speeds up the transition process.
DNF_DRY_RUN_OUTPUT=""

# List of temporary directories scheduled for automated cleanup
declare -a TEMP_DIRS=()

# Current transaction parameters (Stage 2 selection)
SELECTED_INDEX=0                                             # Table identifier number select index
SELECTED_PATH=""                                             # Selected package absolute file path
SELECTED_TYPE=""                                             # Selected package type indicator
SELECTED_NAME=""                                             # Selected package base filename
SELECTED_SIZE=""                                             # Selected package computed file size
SELECTED_SHA256=""                                           # Selected package SHA256 checksum string

# Signature verification status attributes (Stage 3 GPG)
GPG_VERIFIED=false                                           # True if cryptographic check passes successfully
GPG_SIGNER=""                                                # Owner identity of signature key
GPG_KEY_ID=""                                                # Key identifier hash

# Post-operation reporting context
INSTALL_STATUS=""                                            # Result code of final execution ('success' or exit status)
INSTALL_LOCATION=""                                          # Location prefix where files were installed/linked
DEPS_INSTALLED=0                                             # Dependency counter total
DEPS_LIST=""                                                 # String collection of dependencies resolved and added

# ──────────────────────────────────────────────────────────────────────────────
# EARLY SETUP — must succeed or we die
# ──────────────────────────────────────────────────────────────────────────────

# Determine if terminal is interactive and capable of printing formatted/colorized layouts.
# If tput or setaf capabilities are missing, falling back to empty codes to prevent terminal corruptions.
if command -v tput &>/dev/null && tput colors &>/dev/null; then
    HAS_TPUT=true
    C_RED="$(tput setaf 1 2>/dev/null || true)"
    C_GREEN="$(tput setaf 2 2>/dev/null || true)"
    C_YELLOW="$(tput setaf 3 2>/dev/null || true)"
    C_BLUE="$(tput setaf 4 2>/dev/null || true)"
    C_GRAY="$(tput setaf 8 2>/dev/null || true)"
    C_BOLD="$(tput bold 2>/dev/null || true)"
    C_RESET="$(tput sgr0 2>/dev/null || true)"
fi

# ──────────────────────────────────────────────────────────────────────────────
# SAFE EXIT / CLEANUP
# ──────────────────────────────────────────────────────────────────────────────

# Destroys all tracked temporary directories to prevent filesystem pollution.
cleanup() {
    local tmpdir
    for tmpdir in "${TEMP_DIRS[@]}"; do
        if [[ -d "$tmpdir" ]]; then
            rm -rf "$tmpdir" 2>/dev/null || true
        fi
    done
}

# Gracefully exits script, printing descriptive feedback to user.
abort() {
    local message="${1:-Installation aborted by user.}"
    echo
    echo "${C_YELLOW}${message}${C_RESET}"
    cleanup
    exit 0
}

# Fallback error handler triggered when any statement returns an unhandled failure code.
# Prints failure location line number and status, then performs safety cleanup.
handle_err() {
    local exit_code=$?
    local line=$1
    echo "${C_RED}Unexpected error at line ${line} (exit code ${exit_code}).${C_RESET}" >&2
    echo "${C_YELLOW}The script encountered a problem. Please review the output above.${C_RESET}" >&2
    cleanup
    exit "$exit_code"
}

# Signal handler mapping for interruption events (such as SIGINT / SIGTERM / Ctrl+C)
handle_sigint() {
    echo
    abort "Interrupted by user (Ctrl+C). Cleaning up..."
}

# Bind critical exit signals and exit states to safety hooks:
# - ERR: Trapped immediately upon any step failure.
# - EXIT: Standard cleanup of tmp directories when exiting normally or abruptly.
# - SIGINT & SIGTERM: Intercept signals to trigger safe termination flow.
trap 'handle_err $LINENO' ERR
trap cleanup EXIT
trap handle_sigint SIGINT
trap handle_sigint SIGTERM

# ──────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────

# Text style wrapper functions to enhance console output readability
echo_bold()   { echo "${C_BOLD}$*${C_RESET}"; }            # Print bolded text
echo_red()    { echo "${C_RED}$*${C_RESET}"; }             # Print red error/danger text
echo_green()  { echo "${C_GREEN}$*${C_RESET}"; }           # Print green success/safe text
echo_yellow() { echo "${C_YELLOW}$*${C_RESET}"; }          # Print yellow caution/warning text
echo_blue()   { echo "${C_BLUE}$*${C_RESET}"; }            # Print blue informational text
echo_gray()   { echo "${C_GRAY}$*${C_RESET}"; }            # Print gray secondary text

# Structured status tags prefixing actions with risk assessment classifications
log_safe()    { echo " ${C_GREEN}[SAFE]${C_RESET} $*"; }    # Low risk, fully reversible operation
log_caution() { echo " ${C_YELLOW}[CAUTION]${C_RESET} $*"; } # Moderate risk, requires verification
log_danger()  { echo " ${C_RED}[DANGER]${C_RESET} $*"; }   # High risk, could modify system/user binaries/state
log_info()    { echo " ${C_BLUE}[INFO]${C_RESET} $*"; }     # General system intelligence logs

# Prints a centered text string inside a double-bordered box
print_box() {
    local title="$1"
    local width=68
    local padding=0
    local title_len=${#title}
    # Calculate spacing to center the title string
    (( padding = (width - title_len - 2) > 0 ? (width - title_len - 2) : 0 ))
    local left pad_right
    (( left = padding / 2 ))
    (( pad_right = padding - left ))

    echo "${C_BOLD}╔$(printf '═%.0s' $(seq 1 "$width"))╗${C_RESET}"
    printf "${C_BOLD}║${C_RESET}%*s%s%*s${C_BOLD}║${C_RESET}\n" "$left" "" "$title" "$pad_right" ""
    echo "${C_BOLD}╚$(printf '═%.0s' $(seq 1 "$width"))╝${C_RESET}"
}

# Prints two values structured as aligned metadata columns
print_kv() {
    printf "  %-20s %s\n" "$1:" "$2"
}

# Queries user for Yes/No confirmation, enforcing defaults if input is empty.
# Returns: 0 for Yes, 1 for No.
ask_yes_no() {
    local prompt="$1"
    local default="${2:-}"
    local yn=""
    local prompt_str=""

    # Format the prompt tail showing defaults
    if [[ "$default" == "Y" ]]; then
        prompt_str="${prompt} [Y/n]: "
    elif [[ "$default" == "N" ]]; then
        prompt_str="${prompt} [y/N]: "
    else
        prompt_str="${prompt} [y/N]: "
        default="N"
    fi

    while true; do
        read -r -p "$prompt_str" yn
        yn="${yn:-$default}"
        case "$yn" in
            [Yy]*) return 0 ;;
            [Nn]*) return 1 ;;
            *) echo "Please answer yes or no." ;;
        esac
    done
}

# Enforces a strict explicit word input check before allowing execution to proceed.
# Used on highly dangerous/destructive steps (such as package conflicts or removals).
confirm_type_word() {
    local required_word="$1"
    local message="$2"
    local input=""

    echo "${C_RED}${message}${C_RESET}"
    echo
    read -r -p "Type '${required_word}' to confirm: " input
    if [[ "$input" != "$required_word" ]]; then
        echo "${C_YELLOW}Confirmation failed. Aborting.${C_RESET}"
        return 1
    fi
    return 0
}

# Wraps standard prompt reads, capturing exit codes 'q' or '0' to trigger immediate safe termination.
read_with_quit() {
    local prompt_str="$1"
    local input_var
    read -r -p "$prompt_str " input_var
    if [[ "$input_var" == "q" ]] || [[ "$input_var" == "0" ]]; then
        abort
    fi
    echo "$input_var"
}

# Converts raw bytes size to readable metrics (KB, MB, GB)
human_size() {
    local bytes="$1"
    if [[ "$bytes" -lt 1024 ]]; then
        echo "${bytes} B"
    elif [[ "$bytes" -lt 1048576 ]]; then
        echo "$(( bytes / 1024 )) KB"
    elif [[ "$bytes" -lt 1073741824 ]]; then
        echo "$(( bytes / 1048576 )) MB"
    else
        echo "$(( bytes / 1073741824 )) GB"
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 0 — ENVIRONMENT PRE-FLIGHT CHECKS
# ──────────────────────────────────────────────────────────────────────────────

# Evaluates machine health, system packages, operating systems, and internet connectivity.
# Builds lists of warnings (non-fatal issues) and critical errors (immediate abort reasons).
preflight_checks() {
    local warnings=()
    local critical_errors=()

    # Step 1: Detect exact Linux distribution names and version IDs
    if [[ -f /etc/os-release ]]; then
        OS_NAME="$(grep -oP '^PRETTY_NAME="?\K[^"]+' /etc/os-release || true)"
        OS_VERSION="$(grep -oP '^VERSION_ID="?\K[^"]+' /etc/os-release || true)"
        OS_ID="$(grep -oP '^ID="?\K[^"]+' /etc/os-release || true)"
    fi

    if [[ -z "$OS_NAME" ]]; then
        OS_NAME="Unknown Linux"
    fi

    # Step 2: Detect package manager binaries
    if command -v dnf &>/dev/null; then
        HAS_DNF=true
        PACKAGE_MANAGER="dnf ($(dnf --version 2>/dev/null | head -n 1 || true))"
    fi
    if command -v rpm &>/dev/null; then
        HAS_RPM=true
    fi

    # Step 3: Discourage root executions to prevent global filesystem accidents
    if [[ "$CURRENT_USER" == "root" ]]; then
        IS_ROOT=true
        warnings+=("Running as root — this is not recommended for installing local packages")
    fi

    # Step 4: Check if free space is sufficient (arbitrary safe threshold: 500 MB)
    local avail_kb
    avail_kb="$(df "$START_DIR" --output=avail 2>/dev/null | tail -1 || echo 0)"
    avail_kb="${avail_kb// /}"
    if [[ "$avail_kb" =~ ^[0-9]+$ ]]; then
        DISK_SPACE_AVAIL="$(( avail_kb / 1024 )) MB"
        if [[ "$avail_kb" -lt 512000 ]]; then
            DISK_SPACE_WARN=true
            warnings+=("Low disk space in $(pwd): ${DISK_SPACE_AVAIL}")
        fi
    else
        DISK_SPACE_AVAIL="unknown"
    fi

    # Step 5: Internet check — TRULY passive: inspect routing table only, never send data.
    # 'ip route get' resolves the next-hop for an address without transmitting anything.
    if command -v ip &>/dev/null && ip route get 1.1.1.1 &>/dev/null 2>&1; then
        HAS_INTERNET=true
    elif [[ -d /sys/class/net ]]; then
        # Fallback: any non-loopback interface that is UP implies connectivity.
        local iface
        for iface in /sys/class/net/*; do
            local ifname
            ifname="$(basename "$iface")"
            if [[ "$ifname" != "lo" ]] && [[ "$(cat "$iface/operstate" 2>/dev/null)" == "up" ]]; then
                HAS_INTERNET=true
                break
            fi
        done
    fi

    # Step 6: Identify availability of FUSE layers (essential for mounting AppImages)
    if rpm -q fuse &>/dev/null || rpm -q fuse-libs &>/dev/null; then
        HAS_FUSE=true
    fi
    # Also check for fuse3
    if rpm -q fuse3 &>/dev/null || rpm -q fuse3-libs &>/dev/null; then
        HAS_FUSE=true
    fi

    # Step 7: Identify signature verification command utilities
    if command -v gpg &>/dev/null; then
        HAS_GPG=true
    fi

    # Step 8: Identify graphics shell session environments (necessary for desktop shortcut creations)
    DESKTOP_ENV="${XDG_CURRENT_DESKTOP:-${DESKTOP_SESSION:-not detected}}"
    if [[ -n "${XDG_CURRENT_DESKTOP:-}" ]] || [[ -n "${DESKTOP_SESSION:-}" ]]; then
        HAS_DESKTOP=true
    fi

    # Step 9: Check update database helper presence for shortcut updates
    if command -v update-desktop-database &>/dev/null; then
        HAS_UPDATE_DESKTOP_DB=true
    fi

    # Step 10: Enforce existence of essential system commands
    if ! command -v file &>/dev/null; then
        critical_errors+=("'file' command not found (install with: sudo dnf install file)")
    else
        HAS_FILE_CMD=true
    fi

    if ! command -v du &>/dev/null; then
        critical_errors+=("'du' command not found")
    else
        HAS_DU_CMD=true
    fi

    if ! command -v sha256sum &>/dev/null; then
        critical_errors+=("'sha256sum' command not found (install with: sudo dnf install coreutils)")
    else
        HAS_SHA256SUM=true
    fi

    if ! command -v mktemp &>/dev/null; then
        critical_errors+=("'mktemp' command not found (install with: sudo dnf install coreutils)")
    else
        HAS_MKTEMP=true
    fi

    # Step 11: Assert presence of the DNF manager on host
    if ! $HAS_DNF; then
        critical_errors+=("DNF package manager not found — this script requires Fedora Linux with DNF")
    fi

    # Step 12: Warn if OS is outside targeted platform definitions (RHEL ecosystem/Fedora)
    if [[ -n "$OS_ID" ]] && [[ "$OS_ID" != "fedora" ]] && \
       [[ "$OS_ID" != "rhel" ]]  && [[ "$OS_ID" != "centos" ]] && \
       [[ "$OS_ID" != "almalinux" ]] && [[ "$OS_ID" != "rocky" ]] && \
       [[ "$OS_ID" != "ol" ]]; then
        warnings+=("Unrecognised OS: ${OS_NAME} (ID=${OS_ID}). Script targets Fedora/RHEL family — proceed with caution.")
    fi

    # Act on results: Immediate halt if any critical checks failed
    if [[ ${#critical_errors[@]} -gt 0 ]]; then
        echo
        print_box "PRE-FLIGHT CHECK FAILED"
        echo
        echo_red "  Critical issues found — cannot continue:"
        echo
        local err
        for err in "${critical_errors[@]}"; do
            echo "  ❌  ${err}"
        done
        echo
        echo "  Please resolve the above issues and re-run the script."
        echo
        exit 1
    fi

    # Show non-fatal concerns to user and prompt for explicit continuation approval
    if [[ ${#warnings[@]} -gt 0 ]]; then
        echo
        echo_bold "╔════════════════════════════════════════════════════════════════╗"
        echo_bold "║              ENVIRONMENT WARNINGS                            ║"
        echo_bold "╚════════════════════════════════════════════════════════════════╝"
        echo
        local warn
        for warn in "${warnings[@]}"; do
            echo "  ${C_YELLOW}⚠${C_RESET}  ${warn}"
        done
        echo
        if ! ask_yes_no "Continue despite warnings?" "N"; then
            abort "Aborted by user due to warnings."
        fi
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 1 — PACKAGE DISCOVERY
# ──────────────────────────────────────────────────────────────────────────────

# Scans the execution working directory for local target files (.rpm and .AppImage).
# Populates global lists and prints a formatted selection table of the findings.
discover_packages() {
    local i=0
    local path=""
    local size_str=""
    local sha=""
    local fname=""

    echo
    print_box "SCANNING FOR PACKAGES"
    echo
    echo "  Scanning: ${START_DIR}"
    echo

    # Step 1: Scan for RPM files in the current folder (case-insensitive)
    while IFS= read -r -d '' path; do
        if [[ -f "$path" ]]; then
            fname="$(basename "$path")"
            # Get lowercase file extension to verify format
            local lower
            lower="$(echo "$fname" | tr '[:upper:]' '[:lower:]')"
            local ext="${lower##*.}"
            if [[ "$ext" == "rpm" ]]; then
                size_str="$(du -sh "$path" 2>/dev/null | cut -f1)"
                sha="$(sha256sum "$path" 2>/dev/null | cut -d' ' -f1)"
                RPM_FILES+=("$path")
                ALL_PACKAGES+=("RPM | $fname | $size_str")
                ALL_PACKAGES_TYPES+=("RPM")
                ALL_PACKAGES_PATHS+=("$path")
                ALL_PACKAGES_SIZES+=("$size_str")
                ALL_PACKAGES_SHA256+=("$sha")
            fi
        fi
    done < <(find "$START_DIR" -maxdepth 1 -type f -iname '*.rpm' -print0 2>/dev/null)

    # Step 2: Scan for AppImage files in the current folder (case-insensitive)
    while IFS= read -r -d '' path; do
        if [[ -f "$path" ]]; then
            fname="$(basename "$path")"
            local lower
            lower="$(echo "$fname" | tr '[:upper:]' '[:lower:]')"
            if [[ "$lower" == *".appimage" ]] || [[ "$lower" == *"appimage" ]]; then
                size_str="$(du -sh "$path" 2>/dev/null | cut -f1)"
                sha="$(sha256sum "$path" 2>/dev/null | cut -d' ' -f1)"
                APPIMAGE_FILES+=("$path")
                ALL_PACKAGES+=("AppImage | $fname | $size_str")
                ALL_PACKAGES_TYPES+=("AppImage")
                ALL_PACKAGES_PATHS+=("$path")
                ALL_PACKAGES_SIZES+=("$size_str")
                ALL_PACKAGES_SHA256+=("$sha")
            fi
        fi
    done < <(find "$START_DIR" -maxdepth 1 -type f -iname '*.appimage*' -print0 2>/dev/null)

    local total="${#ALL_PACKAGES[@]}"

    # Step 3: Handle empty scan results gracefully and advise location shift
    if [[ "$total" -eq 0 ]]; then
        echo "  ${C_YELLOW}No .rpm or .AppImage files found in the current directory.${C_RESET}"
        echo
        echo "  The script looks for files matching:"
        echo "    • *.rpm (case-insensitive)"
        echo "    • *.AppImage / *.appimage (case-insensitive)"
        echo
        echo "  Navigate to a directory containing packages and re-run."
        echo
        exit 0
    fi

    echo "  Found ${total} package(s) in $(pwd):"
    echo

    # Step 4: Display discovered packages inside a cleanly aligned ASCII table
    # ── TABLE HEADER ──────────────────────────────────────────────────────
    echo "${C_BOLD}  ┌──────┬────────────┬──────────────────────────────────────┬──────────┬──────────────┐${C_RESET}"
    printf "  ${C_BOLD}│${C_RESET} %-3s ${C_BOLD}│${C_RESET} %-10s ${C_BOLD}│${C_RESET} %-36s ${C_BOLD}│${C_RESET} %-8s ${C_BOLD}│${C_RESET} %-12s ${C_BOLD}│${C_RESET}\n" "#" "Type" "Name" "Size" "Arch/SHA"
    echo "${C_BOLD}  ├──────┼────────────┼──────────────────────────────────────┼──────────┼──────────────┤${C_RESET}"

    # ── TABLE ROWS ────────────────────────────────────────────────────────
    local idx=1
    for path in "${ALL_PACKAGES_PATHS[@]}"; do
        local type="${ALL_PACKAGES_TYPES[$((idx-1))]}"
        local size="${ALL_PACKAGES_SIZES[$((idx-1))]}"
        local sha_short="${ALL_PACKAGES_SHA256[$((idx-1))]:0:10}"
        local fname="$(basename "$path")"
        local arch=""
        local name_display=""

        if [[ "$type" == "RPM" ]]; then
            # Query RPM file metadata to read real app name, version, and architecture target
            name_display="$(rpm -qp --queryformat '%{name}-%{version}-%{release}' "$path" 2>/dev/null || echo "$fname")"
            arch="$(rpm -qp --queryformat '%{arch}' "$path" 2>/dev/null || echo "?")"
        else
            # AppImages display filename directly, showing starting SHA hash as version/ident
            name_display="$fname"
            arch="${sha_short}…"
        fi

        # Truncate displays exceeding column limits to preserve layout structure
        local name_trunc="${name_display:0:36}"

        printf "  ${C_BOLD}│${C_RESET} %-3d ${C_BOLD}│${C_RESET} ${C_BOLD}%-10s${C_RESET} ${C_BOLD}│${C_RESET} %-36s ${C_BOLD}│${C_RESET} %-8s ${C_BOLD}│${C_RESET} %-12s ${C_BOLD}│${C_RESET}\n" \
            "$idx" "$type" "$name_trunc" "$size" "$arch"

        ((idx++))
    done

    echo "${C_BOLD}  └──────┴────────────┴──────────────────────────────────────┴──────────┴──────────────┘${C_RESET}"
    echo
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 2 — PACKAGE SELECTION & RISK ANALYSIS
# ──────────────────────────────────────────────────────────────────────────────

# Interactively prompts user for selection index from discovery list.
# Supports abort inputs like 'q' or '0' to exit cleanly.
select_package() {
    local total="${#ALL_PACKAGES[@]}"
    local input=""
    local idx=0

    while true; do
        read -r -p "  Select a package by number (or 'q' to quit): " input
        if [[ "$input" == "q" ]] || [[ "$input" == "0" ]]; then
            abort
        fi
        if ! [[ "$input" =~ ^[0-9]+$ ]]; then
            echo "  ${C_YELLOW}Please enter a valid number.${C_RESET}"
            continue
        fi
        idx="$((10#$input))"
        if [[ "$idx" -lt 1 ]] || [[ "$idx" -gt "$total" ]]; then
            echo "  ${C_YELLOW}Number out of range. Please enter 1-${total}.${C_RESET}"
            continue
        fi
        break
    done

    # Map selected package information to target globals
    SELECTED_INDEX="$idx"
    SELECTED_PATH="${ALL_PACKAGES_PATHS[$((idx-1))]}"
    SELECTED_TYPE="${ALL_PACKAGES_TYPES[$((idx-1))]}"
    SELECTED_SIZE="${ALL_PACKAGES_SIZES[$((idx-1))]}"
    SELECTED_SHA256="${ALL_PACKAGES_SHA256[$((idx-1))]}"
    SELECTED_NAME="$(basename "$SELECTED_PATH")"

    echo
    echo "  Selected: ${SELECTED_NAME}"
}

# Conducts dependency dry-runs with DNF.
# Warns user if removals, GPG issues, conflicts, or external packages are found.
risk_analysis() {
    local dry_run_output=""
    local deps_to_install=""
    local deps_count=0
    local deps_size=""
    local to_upgrade=0
    local to_remove=0
    local removed_pkgs=""
    local has_conflicts=false
    local conflict_details=""
    local has_unsigned=false
    local has_external_deps=false
    local external_deps=""
    local warning_details=""
    local safe_indicators=""
    local danger_exists=false

    if [[ "$SELECTED_TYPE" != "RPM" ]]; then
        return 0  # For AppImage, detailed dependency risk analysis is not applicable
    fi

    echo
    echo_bold "  ┌────────── RISK ANALYSIS REPORT ─────────────────────────────────┐"

    local rpm_name=""
    local rpm_arch=""
    local rpm_version=""

    # Extract target RPM metadata values for console reporting
    rpm_name="$(rpm -qp --queryformat '%{name}' "$SELECTED_PATH" 2>/dev/null || echo "unknown")"
    rpm_version="$(rpm -qp --queryformat '%{version}-%{release}' "$SELECTED_PATH" 2>/dev/null || echo "unknown")"
    rpm_arch="$(rpm -qp --queryformat '%{arch}' "$SELECTED_PATH" 2>/dev/null || echo "unknown")"

    echo "  │ Package:      ${rpm_name}-${rpm_version}.${rpm_arch}.rpm"
    echo "  │ Size on disk: ${SELECTED_SIZE}"
    echo "  │ SHA256:       ${SELECTED_SHA256:0:20}..."
    echo "  │"

    # Run dry-run with DNF — result cached in DNF_DRY_RUN_OUTPUT so install_rpm() reuses it.
    # Assumeno forces DNF to abort before transaction, yielding complete output safely.
    echo "  │ Running dry-run dependency analysis..."
    if [[ -z "$DNF_DRY_RUN_OUTPUT" ]]; then
        DNF_DRY_RUN_OUTPUT="$(dnf install --assumeno "$SELECTED_PATH" 2>&1 || true)"
    fi
    dry_run_output="$DNF_DRY_RUN_OUTPUT"

    # Parse DNF output logs looking for potential removals
    if echo "$dry_run_output" | grep -q "^Removing"; then
        to_remove="$(echo "$dry_run_output" | grep -c "^Removing" || true)"
        removed_pkgs="$(echo "$dry_run_output" | grep "^Removing" | awk '{print $2}' | tr '\n' ', ' | sed 's/,$//')"
        danger_exists=true
    fi

    # Parse DNF output logs looking for dependency installs
    if echo "$dry_run_output" | grep -q "^Installing"; then
        deps_count="$(echo "$dry_run_output" | grep -c "^Installing" || true)"
        # Subtract main installation package from DNF installation list count
        if [[ "$deps_count" -gt 0 ]]; then
            deps_count=$(( deps_count - 1 ))
            if [[ "$deps_count" -lt 0 ]]; then
                deps_count=0
            fi
        fi
    fi

    # Parse DNF output logs looking for package upgrades
    if echo "$dry_run_output" | grep -q "^Upgrading"; then
        to_upgrade="$(echo "$dry_run_output" | grep -c "^Upgrading" || true)"
    fi

    # Check for direct or indirect library conflicts
    if echo "$dry_run_output" | grep -qi "conflict"; then
        has_conflicts=true
        conflict_details="$(echo "$dry_run_output" | grep -i "conflict" | head -n 5 || true)"
    fi

    # Check for packages not available inside repositories
    if echo "$dry_run_output" | grep -qi "not in repository"; then
        has_external_deps=true
        external_deps="$(echo "$dry_run_output" | grep -i "not in repository" | head -n 5 || true)"
    fi

    # Check if DNF warns that GPG signature validation fails/keys are missing
    if echo "$dry_run_output" | grep -qi "is not signed"; then
        has_unsigned=true
    elif echo "$dry_run_output" | grep -qi "gpg"; then
        if ! echo "$dry_run_output" | grep -qi "verified\|good"; then
            has_unsigned=true
        fi
    fi

    echo "  │ Dependencies to install:    ${deps_count} packages"
    echo "  │ Packages to be upgraded:    ${to_upgrade} package(s)"
    if $danger_exists; then
        echo "  │ ${C_RED}Packages to be REMOVED:     ${to_remove} package(s)${C_RESET}"
        echo "  │ ${C_RED}  - ${removed_pkgs}${C_RESET}"
    else
        echo "  │ Packages to be REMOVED:     ${to_remove} package(s)  ← safe"
    fi

    if $has_conflicts; then
        echo "  │ ${C_RED}Conflicts detected:         YES${C_RESET}"
        echo "  │ ${C_RED}  - ${conflict_details}${C_RESET}"
    else
        echo "  │ Conflicts detected:         NONE  ← safe"
    fi

    echo "  │"

    # Render warnings block detailing identified risks
    warning_details=""
    if $has_unsigned; then
        warning_details+="  │ ${C_YELLOW}⚠${C_RESET}  Package is NOT signed with a known GPG key"$'\n'
    fi
    if $has_external_deps; then
        warning_details+="  │ ${C_YELLOW}⚠${C_RESET}  Package requires dependency not in official repos"$'\n'
        warning_details+="  │ ${C_YELLOW}   ${external_deps}${C_RESET}"$'\n'
    fi

    if [[ -n "$warning_details" ]]; then
        echo "  │ ${C_YELLOW}WARNINGS:${C_RESET}"
        echo -n "$warning_details"
    fi

    # Render safe indicators to reassure user if risks are clean
    safe_indicators=""
    if ! $danger_exists; then
        safe_indicators+="  │ ${C_GREEN}✓${C_RESET}  No existing system packages will be removed"$'\n'
    fi
    if ! $has_conflicts; then
        safe_indicators+="  │ ${C_GREEN}✓${C_RESET}  No library conflicts detected"$'\n'
    fi
    if [[ -n "$safe_indicators" ]]; then
        echo "  │"
        echo "  │ ${C_GREEN}SAFE INDICATORS:${C_RESET}"
        echo -n "$safe_indicators"
    fi

    echo "  │"
    echo_bold "  └──────────────────────────────────────────────────────────────────┘"

    # Preserve dependency numbers for the preview step
    DEPS_INSTALLED="$deps_count"

    # Enforce strict manual text confirmation if transaction risks system packages removal
    if $danger_exists; then
        echo
        echo_red "╔══════════════════════════════════════════════════════════════════════╗"
        echo_red "║                              ⚠  DANGER                              ║"
        echo_red "╠══════════════════════════════════════════════════════════════════════╣"
        echo_red "║ Installing this package will REMOVE the following from your system: ║"
        echo_red "║                                                                      ║"
        local removed_pkg
        IFS=', ' read -ra REMOVED_ARRAY <<< "$removed_pkgs"
        for removed_pkg in "${REMOVED_ARRAY[@]}"; do
            removed_pkg="${removed_pkg#"${removed_pkg%%[![:space:]]*}"}"
            removed_pkg="${removed_pkg%"${removed_pkg##*[![:space:]]}"}"
            if [[ -n "$removed_pkg" ]]; then
                echo_red "║   • ${removed_pkg}                                                   ║"
            fi
        done
        echo_red "║                                                                      ║"
        echo_red "║ This may break existing applications on your system.                 ║"
        echo_red "║ Do you fully understand the consequences?                            ║"
        echo_red "╚══════════════════════════════════════════════════════════════════════╝"
        echo
        if ! confirm_type_word "yes" "Please type 'yes' to confirm you understand the risks:"; then
            abort "Aborted by user due to package removal risk."
        fi
    fi

    # Enforce manual text confirmation if package library conflicts are found
    if $has_conflicts; then
        echo
        echo_red "╔══════════════════════════════════════════════════════════════════════╗"
        echo_red "║                     ⚠  PACKAGE CONFLICTS                            ║"
        echo_red "╠══════════════════════════════════════════════════════════════════════╣"
        echo_red "║ This package conflicts with existing software on your system.       ║"
        echo_red "╚══════════════════════════════════════════════════════════════════════╝"
        echo
        if ! confirm_type_word "yes" "Type 'yes' to proceed despite conflicts:"; then
            abort "Aborted by user due to package conflicts."
        fi
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 3 — GPG SIGNATURE VERIFICATION
# ──────────────────────────────────────────────────────────────────────────────

# Coordinates cryptographic and integrity validation for the target packages.
# RPM files search for local .asc/.sig signature logs or import keys from online servers.
# AppImages undergo a passive SHA256 confirmation check.
gpg_verification() {
    local gpg_choice=""
    local sig_files=()
    local sig_found=""
    local pkg_dir=""
    local pkg_basename=""
    local pkg_name_noext=""

    pkg_dir="$(dirname "$SELECTED_PATH")"
    pkg_basename="$(basename "$SELECTED_PATH")"
    pkg_name_noext="${pkg_basename%.rpm}"

    # For AppImage: offer SHA256 integrity check (no GPG sig standard exists for AppImages)
    if [[ "$SELECTED_TYPE" == "AppImage" ]]; then
        echo
        echo "  ${C_BLUE}ℹ${C_RESET}  AppImages don't use RPM-style GPG signing."
        echo "      You can verify integrity via a SHA256 checksum published by the developer."
        echo
        echo "  Computed SHA256 of ${SELECTED_NAME}:"
        echo "    ${SELECTED_SHA256}"
        echo
        echo "  Compare this value against the checksum published on the official download page."
        echo
        if ask_yes_no "Have you verified the checksum matches the official value?" "N"; then
            echo_green "  ✅  User confirmed checksum matches."
            GPG_VERIFIED=true   # re-use flag to mean 'integrity confirmed'
            GPG_SIGNER="User-confirmed SHA256"
        else
            echo_yellow "  ⚠  Proceeding without checksum confirmation."
        fi
        return 0
    fi

    echo
    print_box "GPG SIGNATURE VERIFICATION"

    # Step 1: Install GnuPG subsystem if absent, asking user for confirmation first
    if ! $HAS_GPG; then
        echo
        echo_yellow "  ⚠  GPG is not installed on your system."
        echo
        echo "  GPG verification confirms a package has not been tampered with"
        echo "  and originates from a trusted publisher."
        echo
        if ask_yes_no "Install gnupg2 now?" "Y"; then
            echo
            echo "  ${C_BLUE}Command:${C_RESET} sudo dnf install gnupg2"
            echo
            if ask_yes_no "Proceed with installation?" "N"; then
                # No -y: let DNF show its own transaction summary for transparency.
                sudo dnf install gnupg2 || {
                    echo_red "  Failed to install gnupg2."
                    if ! ask_yes_no "Continue without GPG verification?" "N"; then
                        abort
                    fi
                }
                if command -v gpg &>/dev/null; then
                    HAS_GPG=true
                fi
            else
                if ! ask_yes_no "Continue without GPG verification?" "N"; then
                    abort
                fi
            fi
        else
            if ! ask_yes_no "Continue without GPG verification?" "N"; then
                abort
            fi
        fi
        if ! $HAS_GPG; then
            return 0
        fi
    fi

    echo
    echo "  ${C_BLUE}ℹ${C_RESET}  GPG verification confirms this package has not been tampered with"
    echo "      and originates from a trusted publisher. Skipping this step is a"
    echo "      security risk for packages from unknown sources."
    echo

    if ask_yes_no "Would you like to verify the GPG signature?" "Y"; then
        # Step 2: Assemble paths of possible local signature documents
        local search_patterns=()
        search_patterns+=("${pkg_dir}/${pkg_name_noext}.asc")
        search_patterns+=("${pkg_dir}/${pkg_name_noext}.sig")
        search_patterns+=("${pkg_dir}/${pkg_basename}.asc")
        search_patterns+=("${pkg_dir}/${pkg_basename}.sig")
        search_patterns+=("${pkg_dir}/SHA256SUMS")
        search_patterns+=("${pkg_dir}/checksums.txt")

        local spath=""
        for spath in "${search_patterns[@]}"; do
            if [[ -f "$spath" ]]; then
                sig_found="$spath"
                sig_files+=("$spath")
            fi
        done

        # Step 3: Run GPG validation check on identified signature files
        if [[ ${#sig_files[@]} -gt 0 ]]; then
            echo
            echo "  ${C_GREEN}Signature file(s) found:${C_RESET}"
            local sfile
            for sfile in "${sig_files[@]}"; do
                echo "    • $(basename "$sfile")"
            done
            echo

            local verify_success=false
            local sfile
            for sfile in "${sig_files[@]}"; do
                echo "  Verifying: gpg --verify \"$(basename "$sfile")\" \"${pkg_basename}\""
                echo
                local verify_output
                verify_output="$(gpg --verify "$sfile" "$SELECTED_PATH" 2>&1 || true)"

                if echo "$verify_output" | grep -qi "good signature"; then
                    verify_success=true
                    GPG_VERIFIED=true
                    # Parse signature owner name and key ID attributes
                    GPG_SIGNER="$(echo "$verify_output" | grep -oP '"([^"]+)"' | head -1 || echo "Unknown")"
                    GPG_KEY_ID="$(echo "$verify_output" | grep -oP 'key ID [0-9A-Fa-f]+' | head -1 || echo "unknown")"
                    break
                fi
            done

            if $verify_success; then
                echo_green "  ✅  SIGNATURE VERIFICATION SUCCESSFUL"
                echo
                echo "  Signer:  ${GPG_SIGNER}"
                echo "  Key ID:  ${GPG_KEY_ID}"
            else
                # Step 4: Handle validation failures, presenting manual bypass options
                echo_red "  ❌  SIGNATURE VERIFICATION FAILED"
                echo_red "      This package may have been tampered with."
                echo
                echo "  Options:"
                echo "    [1] Import the correct GPG key manually"
                echo "    [2] Abort installation (RECOMMENDED)"
                echo "    [3] Skip verification and proceed (NOT recommended)"
                echo
                local gpg_opt
                read -r -p "  Choose an option [1-3]: " gpg_opt
                case "$gpg_opt" in
                    1)
                        echo
                        read -r -p "  Enter GPG key ID or path to key file: " gpg_key_input
                        if [[ -f "$gpg_key_input" ]]; then
                            gpg --import "$gpg_key_input" || echo_red "  Failed to import key."
                        else
                            gpg --keyserver keyserver.ubuntu.com --recv-keys "$gpg_key_input" || \
                            gpg --keyserver keys.openpgp.org --recv-keys "$gpg_key_input" || \
                            echo_red "  Failed to receive key. Check the key ID and try again."
                        fi
                        # Retry verification after key import
                        local retry_output
                        local sfile2
                        for sfile2 in "${sig_files[@]}"; do
                            retry_output="$(gpg --verify "$sfile2" "$SELECTED_PATH" 2>&1 || true)"
                            if echo "$retry_output" | grep -qi "good signature"; then
                                GPG_VERIFIED=true
                                echo_green "  ✅  Signature verified after key import."
                                break
                            fi
                        done
                        if ! $GPG_VERIFIED; then
                            echo_red "  Still cannot verify signature."
                            if ! ask_yes_no "Continue anyway?" "N"; then
                                abort
                            fi
                        fi
                        ;;
                    2)
                        abort "Aborted by user due to GPG verification failure."
                        ;;
                    3)
                        if confirm_type_word "IUNDERSTAND" "Type 'IUNDERSTAND' to skip verification:"; then
                            echo_yellow "  Skipping GPG verification."
                        else
                            abort
                        fi
                        ;;
                    *)
                        abort "Invalid option."
                        ;;
                esac
            fi
        else
            # Step 5: Handle absent signature files gracefully
            echo
            echo_yellow "  ⚠  No signature file was found in the current directory."
            echo "      This does not mean the package is unsafe, but it cannot"
            echo "      be cryptographically verified at this time."
            echo
            echo "  Options:"
            echo "    [1] Enter a GPG key ID manually to attempt verification"
            echo "    [2] Search for the publisher's GPG key online (display instructions)"
            echo "    [3] Skip verification and proceed (require confirmation)"
            echo "    [4] Abort and return to package selection"
            echo
            local gpg_opt2
            read -r -p "  Choose an option [1-4]: " gpg_opt2
            case "$gpg_opt2" in
                1)
                    read -r -p "  Enter GPG key ID: " gpg_key_input2
                    gpg --keyserver keyserver.ubuntu.com --recv-keys "$gpg_key_input2" 2>/dev/null || \
                    gpg --keyserver keys.openpgp.org --recv-keys "$gpg_key_input2" 2>/dev/null || \
                    echo_red "  Failed to receive key."
                    # Attempt verification retries
                    local sfile3
                    for sfile3 in "${sig_files[@]}"; do
                        local retry2
                        retry2="$(gpg --verify "$sfile3" "$SELECTED_PATH" 2>&1 || true)"
                        if echo "$retry2" | grep -qi "good signature"; then
                            GPG_VERIFIED=true
                            echo_green "  ✅  Signature verified."
                            break
                        fi
                    done
                    if ! $GPG_VERIFIED; then
                        echo_red "  Could not verify signature with provided key."
                        if ! ask_yes_no "Continue without verification?" "N"; then
                            abort
                        fi
                    fi
                    ;;
                2)
                    echo
                    echo "  To find the publisher's GPG key:"
                    echo "    1. Visit the publisher's official website"
                    echo "    2. Look for a 'Security' or 'Downloads' section"
                    echo "    3. Download their public GPG key file"
                    echo "    4. Import it: gpg --import <keyfile>"
                    echo "    5. Re-run verification with this script"
                    echo
                    if ! ask_yes_no "Continue without verification?" "N"; then
                        abort
                    fi
                    ;;
                3)
                    if confirm_type_word "IUNDERSTAND" "Type 'IUNDERSTAND' to skip verification:"; then
                        echo_yellow "  Skipping GPG verification."
                    else
                        abort
                    fi
                    ;;
                4)
                    abort
                    ;;
                *)
                    abort "Invalid option."
                    ;;
            esac
        fi
    else
        echo
        echo_yellow "  ⚠  You are proceeding without signature verification."
        echo "      Only continue if you downloaded this package from an official,"
        echo "      trusted source and verified its integrity by other means."
        echo
        read -r -p "  Press [Enter] to continue, or [q] to abort: " skip_confirm
        if [[ "$skip_confirm" == "q" ]]; then
            abort
        fi
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 4A — SAFE RPM INSTALLATION
# ──────────────────────────────────────────────────────────────────────────────

# Oversees the final transaction execution of the RPM packages via DNF commands.
# Shows a comprehensive transaction preview detailing changes, sizes, and disk requirements.
install_rpm() {
    local full_path="$SELECTED_PATH"
    local pkg_name=""
    local rpm_arch=""
    local rpm_version=""
    local dry_run_output=""
    local deps_count="${DEPS_INSTALLED}"
    local deps_size_str=""
    local upgrade_count=0
    local remove_count=0
    local space_needed=""

    pkg_name="$(rpm -qp --queryformat '%{name}' "$full_path" 2>/dev/null || echo "unknown")"
    rpm_version="$(rpm -qp --queryformat '%{version}-%{release}' "$full_path" 2>/dev/null || echo "unknown")"
    rpm_arch="$(rpm -qp --queryformat '%{arch}' "$full_path" 2>/dev/null || echo "unknown")"

    # Reuse cached dry-run from risk_analysis() — avoids a second slow DNF call.
    if [[ -n "$DNF_DRY_RUN_OUTPUT" ]]; then
        dry_run_output="$DNF_DRY_RUN_OUTPUT"
    else
        dry_run_output="$(dnf install --assumeno "$full_path" 2>&1 || true)"
        DNF_DRY_RUN_OUTPUT="$dry_run_output"
    fi

    # Extract precise operation counts from dry-run output
    upgrade_count="$(echo "$dry_run_output" | grep -c "^Upgrading" || true)"
    remove_count="$(echo "$dry_run_output" | grep -c "^Removing" || true)"

    echo
    print_box "INSTALLATION PREVIEW"
    echo
    echo "  Command:"
    echo "    sudo dnf install \"${full_path}\""
    echo
    echo "  This will:"
    echo "    ${C_GREEN}✔${C_RESET} Install:  ${pkg_name}-${rpm_version}.${rpm_arch} (${SELECTED_SIZE})"
    if [[ "$deps_count" -gt 0 ]]; then
        echo "    ${C_GREEN}✔${C_RESET} Install dependencies: ${deps_count} package(s)"
    fi
    if [[ "$upgrade_count" -gt 0 ]]; then
        echo "    ${C_GREEN}✔${C_RESET} Upgrade:  ${upgrade_count} package(s)"
    fi
    if [[ "$remove_count" -eq 0 ]]; then
        echo "    ${C_GREEN}✗${C_RESET} Remove:   nothing"
    else
        echo "    ${C_RED}✗${C_RESET} Remove:   ${remove_count} package(s) ← ${C_RED}WARNING${C_RESET}"
    fi
    echo "    ${C_GREEN}✗${C_RESET} Downgrade: nothing"
    echo
    echo "  GPG Verified:  ${GPG_VERIFIED:-${C_YELLOW}No${C_RESET}}"
    echo
    echo "  Disk space required: ~${SELECTED_SIZE}"
    echo "  Available disk space: ${DISK_SPACE_AVAIL}"
    echo

    if ! ask_yes_no "Proceed with installation?" "N"; then
        abort "Installation cancelled by user."
    fi

    echo
    echo "  Running: sudo dnf install \"${full_path}\""
    echo

    # Step 1: Run DNF with live console output.
    # We do not capture output here so the user sees progress and GPG prompts live.
    local install_rc=0
    sudo dnf install "$full_path" || install_rc=$?
    if [[ "$install_rc" -ne 0 ]]; then
        local install_output=""
        # Step 2: Re-run silently ONLY on failure to capture error messages for diagnosis.
        {  
        install_output="$(sudo dnf install "$full_path" 2>&1)" || true; } 2>/dev/null
        echo_red "  ❌  Installation failed (exit code: ${install_rc})."
        echo
        if echo "$install_output" | grep -qi "already installed"; then
            echo "  Suggestion: The package appears to already be installed."
        elif echo "$install_output" | grep -qi "nothing provides\|missing dependency\|requires:"; then
            echo "  Suggestion: Missing dependencies. Check that required repos are enabled."
        elif echo "$install_output" | grep -qi "wrong architecture\|arch"; then
            echo "  Suggestion: Package architecture does not match your system."
        else
            echo "  Check the DNF output above for details."
        fi
        return 1
    fi
    if false; then  # dead-code block to satisfy old structure
    local install_output
    install_output="$(sudo dnf install "$full_path" 2>&1)" || {
        local exit_code=$?
        echo_red "  ❌  Installation failed (exit code: ${exit_code})."
        echo
        echo "  DNF output:"
        echo "$install_output"
        echo
        if echo "$install_output" | grep -qi "already installed"; then
            echo "  Suggestion: The package may already be installed."
        elif echo "$install_output" | grep -qi "nothing provides\|missing dependency\|requires:"; then
            echo "  Suggestion: Missing dependencies. Check if all required repos are enabled."
        elif echo "$install_output" | grep -qi "wrong architecture\|arch"; then
            echo "  Suggestion: The package architecture does not match your system."
        elif echo "$install_output" | grep -qi "no match\|not found"; then
            echo "  Suggestion: The file may have been moved or deleted."
        else
            echo "  See the DNF output above for details."
        fi
        return 1
    }
    fi  # end dead-code block

    echo_green "  ✅  Installation completed successfully."

    # Step 3: Query RPM database to record package files destination path
    INSTALL_LOCATION="$(rpm -ql "$pkg_name" 2>/dev/null | head -5 | tr '\n' ' ' || echo "See 'rpm -ql ${pkg_name}'")"
    INSTALL_STATUS="success"

    echo
    print_box "INSTALLATION COMPLETE"
    echo
    echo "  ${C_GREEN}Package:${C_RESET}          ${pkg_name}-${rpm_version}.${rpm_arch}"
    echo "  ${C_GREEN}Type:${C_RESET}             RPM"
    echo "  ${C_GREEN}Source file:${C_RESET}      ${full_path}"
    echo "  ${C_GREEN}SHA256:${C_RESET}           ${SELECTED_SHA256}"
    echo
    if $GPG_VERIFIED; then
        echo "  ${C_GREEN}GPG Verified:     ✅ Yes — ${GPG_SIGNER} (${GPG_KEY_ID})${C_RESET}"
    else
        echo "  ${C_YELLOW}GPG Verified:     ⚠ No${C_RESET}"
    fi
    echo "  ${C_GREEN}Install Status:   ✅ Success${C_RESET}"
    echo "  ${C_GREEN}Install Location: ${INSTALL_LOCATION}${C_RESET}"
    echo "  ${C_GREEN}Disk Space Used:  ~${SELECTED_SIZE}${C_RESET}"
    echo "  ${C_GREEN}Dependencies:     ${DEPS_INSTALLED} package(s) installed${C_RESET}"
    echo
    echo "  Timestamp:        ${TIMESTAMP}"
    echo
    echo "  ${C_BLUE}To uninstall:     sudo dnf remove ${pkg_name}${C_RESET}"
    echo
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 4B — SAFE APPIMAGE INTEGRATION
# ──────────────────────────────────────────────────────────────────────────────

# Configures, registers, and copies AppImage files to target directories.
# Extracts embedded launchers/icons and links them to user environment folders.
install_appimage() {
    local appimage_path="$SELECTED_PATH"
    local appimage_name="$(basename "$appimage_path")"
    # Strip extension case-insensitively to obtain clean basename
    local appimage_lower="${appimage_name,,}"
    local appimage_basename
    if [[ "${appimage_lower##*.}" == "appimage" ]]; then
        appimage_basename="${appimage_name%.*}"
    else
        appimage_basename="$appimage_name"
    fi
    local dest_dir=""
    local dest_path=""
    local choice=""

    echo
    print_box "APPIMAGE INTEGRATION"

    # ── Step 1: Ensure FUSE dependencies are met ────────────────────────
    if ! $HAS_FUSE; then
        echo
        echo_yellow "  ⚠  FUSE is not installed."
        echo
        echo "  AppImages require FUSE (Filesystem in Userspace) to run."
        echo "  Without FUSE, AppImages will not execute."
        echo
        echo "  ${C_BLUE}Fix:${C_RESET} sudo dnf install fuse fuse-libs"
        echo
        if ask_yes_no "Install FUSE now?" "Y"; then
            echo
            # Select modern fuse3 package on modern Fedora with fallback to legacy fuse package
            local fuse_pkg="fuse3 fuse3-libs"
            if ! dnf info fuse3 &>/dev/null 2>&1; then
                fuse_pkg="fuse fuse-libs"
            fi
            echo "  Running: sudo dnf install ${fuse_pkg}"
            # No -y: let user review dependencies list transaction details
            # shellcheck disable=SC2086
            sudo dnf install $fuse_pkg || {
                echo_red "  Failed to install FUSE."
                if ! ask_yes_no "Continue without FUSE? (AppImage will not run)" "N"; then
                    abort
                fi
            }
            # Recheck dependencies status
            if rpm -q fuse &>/dev/null || rpm -q fuse-libs &>/dev/null || \
               rpm -q fuse3 &>/dev/null || rpm -q fuse3-libs &>/dev/null; then
                HAS_FUSE=true
                echo_green "  ✅  FUSE installed."
            fi
        else
            echo_yellow "  Skipping FUSE installation. AppImage may not run."
            if ! ask_yes_no "Continue integration anyway?" "N"; then
                abort
            fi
        fi
    fi

    # ── Step 2: Assign target path directory ─────────────────────────────
    echo
    echo "  Choose destination directory for the AppImage:"
    echo "    [1] ~/Applications/ (recommended — user-local, no sudo needed)"
    echo "    [2] Current directory (leave in place)"
    echo "    [3] Enter custom path"
    echo
    read -r -p "  Choose [1-3]: " choice
    case "$choice" in
        1)
            dest_dir="${HOME}/Applications"
            ;;
        2)
            dest_dir="$START_DIR"
            ;;
        3)
            read -r -p "  Enter custom path: " dest_dir
            dest_dir="${dest_dir/#\~/${HOME}}"
            ;;
        *)
            dest_dir="${HOME}/Applications"
            echo_yellow "  Defaulting to ~/Applications/"
            ;;
    esac

    # Create target directory folder if absent
    if [[ ! -d "$dest_dir" ]]; then
        echo
        echo "  Directory '${dest_dir}' does not exist."
        if ask_yes_no "Create it?" "Y"; then
            mkdir -p "$dest_dir" || {
                echo_red "  Failed to create directory."
                abort
            }
            echo_green "  ✅  Created: ${dest_dir}"
        else
            dest_dir="$START_DIR"
            echo "  Using current directory instead."
        fi
    fi

    dest_path="${dest_dir}/${appimage_name}"

    # ── Step 3: Change permissions and copy executable ──────────────────
    echo
    print_box "PERMISSION CHANGE PREVIEW"
    echo
    echo "  ${C_BLUE}File:${C_RESET}     ${dest_path}"
    echo "  ${C_BLUE}Current:${C_RESET}  $(ls -l "$appimage_path" | awk '{print $1 " (" $3 ":" $4 ")"}')"
    echo "  ${C_BLUE}New:${C_RESET}      -rwxr-xr-x (executable)"
    echo
    echo "  This allows the file to be run as a program."
    echo "  Only do this for AppImages from trusted sources."
    echo

    if ! ask_yes_no "Apply permission change and copy to destination?" "N"; then
        abort "AppImage integration cancelled."
    fi

    echo
    echo "  Copying: ${appimage_path} → ${dest_path}"
    cp "$appimage_path" "$dest_path" || {
        echo_red "  Failed to copy AppImage."
        abort
    }
    chmod +x "$dest_path" || {
        echo_red "  Failed to make AppImage executable."
        abort
    }
    echo_green "  ✅  AppImage copied and made executable."

    # ── Step 4: Extract desktop launcher configuration files ─────────────
    if $HAS_DESKTOP; then
        echo
        echo "  Optionally, create a desktop launcher for the application menu."
        if ask_yes_no "Create desktop launcher?" "Y"; then
            extract_desktop_entry "$dest_path" "$appimage_basename" "$dest_dir" "$appimage_name"
        else
            echo "  Skipping desktop entry."
        fi
    else
        echo
        echo "  ${C_BLUE}ℹ${C_RESET}  No desktop environment detected. Skipping desktop launcher creation."
    fi

    # ── Final report summary ─────────────────────────────────────────────
    echo
    print_box "APPIMAGE INSTALLATION COMPLETE"
    echo
    echo "  ${C_GREEN}Package:${C_RESET}          ${appimage_name}"
    echo "  ${C_GREEN}Type:${C_RESET}             AppImage"
    echo "  ${C_GREEN}Source file:${C_RESET}      ${appimage_path}"
    echo "  ${C_GREEN}SHA256:${C_RESET}           ${SELECTED_SHA256}"
    echo
    echo "  ${C_GREEN}AppImage Location:${C_RESET} ${dest_path}"
    echo "  ${C_GREEN}Executable:${C_RESET}       ✅ Yes"
    if [[ -f "${HOME}/.local/share/applications/${appimage_basename}.desktop" ]]; then
        echo "  ${C_GREEN}Desktop Entry:${C_RESET}     ~/.local/share/applications/${appimage_basename}.desktop"
        echo "  ${C_GREEN}Appears in menu:${C_RESET}   ✅ Yes"
    fi
    if [[ -f "${HOME}/.local/share/icons/${appimage_basename}.png" ]]; then
        echo "  ${C_GREEN}Icon:${C_RESET}              ~/.local/share/icons/${appimage_basename}.png"
    fi
    echo
    echo "  Timestamp:        ${TIMESTAMP}"
    echo
    echo "  ${C_BLUE}To uninstall:${C_RESET}"
    echo "    rm \"${dest_path}\""
    if [[ -f "${HOME}/.local/share/applications/${appimage_basename}.desktop" ]]; then
        echo "    rm \"${HOME}/.local/share/applications/${appimage_basename}.desktop\""
    fi
    if [[ -f "${HOME}/.local/share/icons/${appimage_basename}.png" ]]; then
        echo "    rm \"${HOME}/.local/share/icons/${appimage_basename}.png\""
    fi
    echo
}

# Mounts AppImage in secure temporary workspace directory.
# Locates and extracts embedded application shortcuts and graphics icons.
# Uses a multi-strategy icon search: DirIcon standard -> desktop Icon= key ->
# resolution-priority PNG selection -> SVG -> XPM fallback.
extract_desktop_entry() {
    local appimage_path="$1"
    local appimage_basename="$2"
    local dest_dir_arg="${3:-}"
    local appimage_name_arg="${4:-}"
    local tmpdir=""
    local icon_file=""
    local desktop_file=""
    local extracted_icon=""
    local extracted_desktop=""
    local icon_ext=""

    tmpdir="$(mktemp -d)"
    TEMP_DIRS+=("$tmpdir")

    echo
    echo "  Extracting AppImage metadata (temporary)..."
    echo "  This may take a moment for large AppImages."

    cp "$appimage_path" "$tmpdir/" || return 1
    local tmp_appimage="${tmpdir}/$(basename "$appimage_path")"
    chmod +x "$tmp_appimage" || return 1

    # Execute extraction tool built into AppImage structures
    echo
    echo "  ${C_BLUE}Command:${C_RESET} ${tmp_appimage##*/} --appimage-extract"
    echo
    if (cd "$tmpdir" && "$tmp_appimage" --appimage-extract 2>/dev/null); then
        echo "  Extraction successful."
    else
        echo_yellow "  Extraction failed. The AppImage may not support extraction."
        echo "  A launcher can still be created manually."
        if ! ask_yes_no "Create basic desktop entry without icon?" "N"; then
            return 1
        fi
        create_manual_desktop "$appimage_path" "$appimage_basename" "" "$appimage_basename"
        return 0
    fi

    local squash_dir="${tmpdir}/squashfs-root"
    if [[ ! -d "$squash_dir" ]]; then
        echo_yellow "  No squashfs-root directory found after extraction."
        if ! ask_yes_no "Create basic desktop entry without icon?" "N"; then
            return 1
        fi
        create_manual_desktop "$appimage_path" "$appimage_basename" "" "$appimage_basename"
        return 0
    fi

    # ── ICON EXTRACTION ──────────────────────────────────────────────────
    # Strategy priorities for icon candidate selection:
    #   1. .DirIcon — AppImage standard root icon file
    #   2. Icon referenced by .desktop Icon= key (resolved against squashfs-root)
    #   3. Highest-resolution PNG matching the application name
    #   4. Any largest PNG in the extracted tree
    #   5. Any SVG icon
    #   6. Any XPM icon as last resort
    echo
    echo "  ${C_BLUE}Searching for embedded icons...${C_RESET}"

    local chosen_icon=""

    # Strategy 1: .DirIcon (AppImage standard icon at the root of the image)
    if [[ -f "${squash_dir}/.DirIcon" ]]; then
        chosen_icon="${squash_dir}/.DirIcon"
        echo "  ${C_GREEN}Found .DirIcon${C_RESET} (AppImage standard icon)"
    fi

    # Strategy 2: Parse every .desktop file for Icon= key and resolve the
    # referenced icon name against files in squashfs-root.
    # Desktop Icon keys often reference names like "app" or "app-icon"
    # without extension. We resolve by searching for exact match with extensions.
    if [[ -z "$chosen_icon" ]]; then
        local desktop_candidates=()
        while IFS= read -r -d '' dcand; do
            desktop_candidates+=("$dcand")
        done < <(find "$squash_dir" -maxdepth 3 -type f -iname '*.desktop' -print0 2>/dev/null)

        for dcand in "${desktop_candidates[@]}"; do
            local icon_key
            icon_key="$(grep -i '^Icon=' "$dcand" 2>/dev/null | head -1 || true)"
            if [[ -n "$icon_key" ]]; then
                local icon_name="${icon_key#Icon=}"
                icon_name="${icon_name%% *}"
                # Try resolving icon_name against files in squashfs-root
                # First: exact match with extension
                local resolved=""
                for ext in svg png xpm; do
                    # Search in typical icon directories first
                    resolved="$(find "$squash_dir" -type f -iname "${icon_name}.${ext}" -print -quit 2>/dev/null || true)"
                    if [[ -n "$resolved" ]]; then
                        chosen_icon="$resolved"
                        echo "  ${C_GREEN}Resolved icon from .desktop Icon= key:${C_RESET} $(basename "$resolved")"
                        break 2
                    fi
                done
                # Also try icon_name as a prefix (e.g., Icon=app → app-256.png)
                if [[ -z "$chosen_icon" ]]; then
                    for ext in svg png xpm; do
                        resolved="$(find "$squash_dir" -type f -iname "${icon_name}*.${ext}" -print -quit 2>/dev/null || true)"
                        if [[ -n "$resolved" ]]; then
                            chosen_icon="$resolved"
                            echo "  ${C_GREEN}Resolved icon from .desktop Icon= key:${C_RESET} $(basename "$resolved")"
                            break 2
                        fi
                    done
                fi
            fi
        done
    fi

    # Strategy 3: Highest-resolution PNG matching the application basename
    if [[ -z "$chosen_icon" ]]; then
        local best_png=""
        local best_size=0
        local png_candidate
        while IFS= read -r -d '' png_candidate; do
            local fname_lower
            fname_lower="$(basename "$png_candidate" | tr '[:upper:]' '[:lower:]')"
            local candidate_size=0
            # Extract resolution hints from filename (e.g. app-256x256.png, app_128.png, 256.png)
            if [[ "$fname_lower" =~ ([0-9]+)x[0-9]+ ]]; then
                candidate_size="${BASH_REMATCH[1]}"
            elif [[ "$fname_lower" =~ [-_]([0-9]+)[._] ]]; then
                candidate_size="${BASH_REMATCH[1]}"
            elif [[ "$fname_lower" =~ [-_]([0-9]+)\.png ]]; then
                candidate_size="${BASH_REMATCH[1]}"
            fi
            # If the filename contains the app name, boost its priority higher
            local app_lower
            app_lower="$(echo "$appimage_basename" | tr '[:upper:]' '[:lower:]')"
            if [[ "$fname_lower" == *"${app_lower}"* ]]; then
                (( candidate_size += 1000 )) || true
            fi
            if [[ "$candidate_size" -gt "$best_size" ]]; then
                best_size="$candidate_size"
                best_png="$png_candidate"
            fi
        done < <(find "$squash_dir" -type f -iname '*.png' -print0 2>/dev/null)
        if [[ -n "$best_png" ]]; then
            chosen_icon="$best_png"
            echo "  ${C_GREEN}Found PNG icon by resolution priority:${C_RESET} $(basename "$best_png")"
        fi
    fi

    # Strategy 4: Any PNG (first found)
    if [[ -z "$chosen_icon" ]]; then
        local any_png
        any_png="$(find "$squash_dir" -type f -iname '*.png' -print -quit 2>/dev/null || true)"
        if [[ -n "$any_png" ]]; then
            chosen_icon="$any_png"
            echo "  ${C_GREEN}Found PNG icon:${C_RESET} $(basename "$any_png")"
        fi
    fi

    # Strategy 5: SVG icon
    if [[ -z "$chosen_icon" ]]; then
        local any_svg
        any_svg="$(find "$squash_dir" -type f -iname '*.svg' -print -quit 2>/dev/null || true)"
        if [[ -n "$any_svg" ]]; then
            chosen_icon="$any_svg"
            echo "  ${C_GREEN}Found SVG icon:${C_RESET} $(basename "$any_svg")"
        fi
    fi

    # Strategy 6: XPM icon as last resort
    if [[ -z "$chosen_icon" ]]; then
        local any_xpm
        any_xpm="$(find "$squash_dir" -type f -iname '*.xpm' -print -quit 2>/dev/null || true)"
        if [[ -n "$any_xpm" ]]; then
            chosen_icon="$any_xpm"
            echo "  ${C_GREEN}Found XPM icon:${C_RESET} $(basename "$any_xpm")"
        fi
    fi

    # Install the chosen icon to user icons directory
    icon_file=""
    if [[ -n "$chosen_icon" ]]; then
        local icon_filename
        icon_filename="$(basename "$chosen_icon")"
        icon_ext="${icon_filename##*.}"
        local icon_ext_lower
        icon_ext_lower="$(echo "$icon_ext" | tr '[:upper:]' '[:lower:]')"

        # Determine final extension — SVG gets installed as-is since desktop
        # environments natively support them. PNG and XPM keep their format.
        # XPM is converted to PNG if ImageMagick is available for better support.
        local final_ext="$icon_ext_lower"
        if [[ "$icon_ext_lower" == "xpm" ]]; then
            if command -v convert &>/dev/null; then
                final_ext="png"
            fi
        fi

        echo
        echo "  ┌── ICON INSTALLATION PREVIEW ─────────────────────────────────┐"
        echo "  │ Source:      ${icon_filename}"
        echo "  │ Destination: ~/.local/share/icons/${appimage_basename}.${final_ext}"
        echo "  │ Format:      ${icon_ext_lower} → ${final_ext}"
        echo "  └──────────────────────────────────────────────────────────────────┘"
        echo

        if ask_yes_no "Install this icon to ~/.local/share/icons/?" "Y"; then
            local icon_dest="${HOME}/.local/share/icons/${appimage_basename}.${final_ext}"
            mkdir -p "${HOME}/.local/share/icons"
            cp "$chosen_icon" "$icon_dest" || {
                echo_yellow "  Failed to copy icon."
                icon_file=""
            }
            # Convert XPM to PNG if ImageMagick convert is present
            if [[ "$icon_ext_lower" == "xpm" ]] && command -v convert &>/dev/null; then
                convert "$icon_dest" "${HOME}/.local/share/icons/${appimage_basename}.png" 2>/dev/null || true
                # Remove original xpm copy since we have the PNG conversion
                rm -f "${icon_dest}" 2>/dev/null || true
                icon_dest="${HOME}/.local/share/icons/${appimage_basename}.png"
            fi
            icon_file="$icon_dest"
            echo_green "  ✅  Icon installed to ${icon_dest}"
        fi
    else
        echo_yellow "  No icon files found inside AppImage."
        echo "  The desktop entry will use a generic application icon."
    fi

    # ── DESKTOP ENTRY EXTRACTION ──────────────────────────────────────
    # Step 1: Search for .desktop launcher files in the extracted content
    echo
    echo "  ${C_BLUE}Searching for embedded .desktop launchers...${C_RESET}"

    local search_desktop
    search_desktop="$(find "$squash_dir" -maxdepth 3 -type f -iname '*.desktop' 2>/dev/null | head -n 1 || true)"
    if [[ -n "$search_desktop" ]]; then
        extracted_desktop="$search_desktop"
        echo "  ${C_GREEN}Desktop entry found:${C_RESET} $(basename "$extracted_desktop")"
        echo

        echo "  Original desktop file contents:"
        echo "  ─────────────────────────────────────────────────────"
        while IFS= read -r dline; do
            echo "    ${dline}"
        done < "$extracted_desktop"
        echo "  ─────────────────────────────────────────────────────"
        echo

        # Step 2: Rebuild absolute paths for executable/icon mappings inside
        # desktop configuration file — ensure Exec= and Icon= point to final locations
        local modified_desktop="${tmpdir}/modified.desktop"
        local exec_path="${appimage_path}"
        # Override exec path if dest_dir was provided and file exists there
        if [[ -n "$dest_dir_arg" ]] && [[ -n "$appimage_name_arg" ]] && [[ -f "${dest_dir_arg}/${appimage_name_arg}" ]]; then
            exec_path="${dest_dir_arg}/${appimage_name_arg}"
        fi
        local icon_path="${icon_file:-${appimage_basename}}"

        # Write modified desktop entry: rewrite Exec= and Icon= lines to use
        # the real installed location of the AppImage binary and the icon.
        # Also strip any %F/%U arguments that may reference old paths.
        : > "$modified_desktop"
        while IFS= read -r dline; do
            if [[ "$dline" =~ ^Exec= ]]; then
                # Preserve any %F/%U etc. arguments from original Exec line
                local exec_args=""
                local orig_exec="$dline"
                orig_exec="${orig_exec#Exec=}"
                # Extract trailing % placeholders (like %F, %U, %f, %u)
                exec_args="$(echo "$orig_exec" | grep -oP '%[fFuUcCdDnNickvm]+' || true)"
                echo "Exec=${exec_path} ${exec_args}" >> "$modified_desktop"
            elif [[ "$dline" =~ ^Icon= ]]; then
                echo "Icon=${icon_path}" >> "$modified_desktop"
            else
                echo "$dline" >> "$modified_desktop"
            fi
        done < "$extracted_desktop"

        # Show reconstructed desktop entry file preview before writing to filesystem
        echo "  Modified desktop entry (will be written):"
        echo "  ┌── DESKTOP ENTRY PREVIEW ─────────────────────────────────┐"
        while IFS= read -r dline; do
            printf "  │ %-60s │\n" "$dline"
        done < "$modified_desktop"
        echo "  └──────────────────────────────────────────────────────────┘"
        echo

        if ask_yes_no "Write this desktop file?" "Y"; then
            local desktop_dest="${HOME}/.local/share/applications/${appimage_basename}.desktop"
            mkdir -p "${HOME}/.local/share/applications"
            cp "$modified_desktop" "$desktop_dest"
            chmod +x "$desktop_dest"

            # Update graphical databases to show shortcut in system application
            # lists immediately
            if $HAS_UPDATE_DESKTOP_DB; then
                echo "  Running: update-desktop-database ~/.local/share/applications"
                update-desktop-database "${HOME}/.local/share/applications" 2>/dev/null || true
            fi
            echo_green "  ✅  Desktop entry created."
        fi
    else
        echo_yellow "  No .desktop file found in AppImage."
        if ask_yes_no "Create a basic desktop entry manually?" "N"; then
            local icon_param="${icon_file:-}"
            create_manual_desktop "$appimage_path" "$appimage_basename" "$icon_param" "$appimage_basename"
        fi
    fi
}

# Generates basic shortcut file manually if extraction yields no .desktop options.
create_manual_desktop() {
    local exec_path="$1"
    local app_name="$2"
    local icon_path="$3"
    local desktop_name="$4"

    local desktop_content=""
    desktop_content="[Desktop Entry]
Name=${app_name}
Exec=${exec_path}
Icon=${icon_path:-${app_name}}
Type=Application
Categories=Utility;
Terminal=false"

    echo
    echo "  ┌── DESKTOP ENTRY PREVIEW ─────────────────────────────────┐"
    while IFS= read -r dline; do
        printf "  │ %-60s │\n" "$dline"
    done <<< "$desktop_content"
    echo "  └──────────────────────────────────────────────────────────┘"
    echo

    if ask_yes_no "Write this desktop file?" "Y"; then
        local desktop_dest="${HOME}/.local/share/applications/${desktop_name}.desktop"
        mkdir -p "${HOME}/.local/share/applications"
        echo "$desktop_content" > "$desktop_dest"
        chmod +x "$desktop_dest"

        if $HAS_UPDATE_DESKTOP_DB; then
            echo "  Running: update-desktop-database ~/.local/share/applications"
            update-desktop-database "${HOME}/.local/share/applications" 2>/dev/null || true
        fi
        echo_green "  ✅  Desktop entry created."
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

# Main program coordinator routing logic.
# Sequential execution structure of Stage 0 (Checks) -> Stage 1 (Find) -> Stage 2 (Choose) -> Stage 3 (Verify) -> Stage 4 (Install).
main() {
    echo
    print_box "LOCAL PACKAGE INSTALLER"
    echo "  ${C_BLUE}A safe tool for installing local .rpm and .AppImage files${C_RESET}"
    echo "  ${C_GRAY}Run from: ${START_DIR}${C_RESET}"
    echo

    # Stage 0 — Pre-flight checks
    preflight_checks

    # Stage 1 — Package discovery scan
    discover_packages

    # Stage 2 — Selection & risk analysis dry-run
    select_package

    if [[ "$SELECTED_TYPE" == "RPM" ]]; then
        risk_analysis
        gpg_verification
        install_rpm
    elif [[ "$SELECTED_TYPE" == "AppImage" ]]; then
        install_appimage
    fi

    echo
    echo_green "  All operations complete."
    echo
}

main
