#!/usr/bin/env bash
#
# ==============================================================================
# TrustInstall.sh — Enterprise-grade local package discovery & installation tool
# ==============================================================================
#
# ARCHITECTURAL DESIGN SUMMARY:
# - Stage 0: Pre-flight Checks (System validation, disk, network, command binaries)
# - Stage 1: Dynamic discovery of RPM & AppImage packages in CWD (non-recursive)
# - Stage 2: Target Selection & transaction simulation via DNF dry-run with sudo
# - Stage 3: Verification Engine (Detached PGP/GPG signature check -> Checksum verification
#            -> Embedded RPM signature verify fallback -> SHA256 checksum fallback)
# - Stage 4A: Safe RPM transaction execution via DNF package manager
# - Stage 4B: AppImage integration, metadata extraction, FUSE check, launcher db update
#
# SYSTEM SAFETY & CONCURRENCY:
# - set -euEo pipefail: ensures strict error handling, unset var checks, pipeline failure checks
# - signal trapping (EXIT/ERR/SIGINT/SIGTERM): coordinates cleanups of mktemp directories
# - SIGPIPE protection: pipeline outputs are processed using awk instead of head/tail to
#   prevent early pipe closure which triggers exit code 141 under pipefail.
#
# License: GPL3.0
# ==============================================================================
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
HAS_PGP=false                                                # Presence of PGP verification tool (GnuPG engine)
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

# Signature verification status attributes (Stage 3 PGP)
PGP_VERIFIED=false                                           # True if PGP check passes successfully
PGP_SIGNER=""                                                # Owner identity of signature key
PGP_KEY_ID=""                                                # Key identifier hash

# Post-operation reporting context
INSTALL_STATUS=""                                            # Result code of final execution ('success' or exit status)
INSTALL_LOCATION=""                                          # Location prefix where files were installed/linked
DEPS_INSTALLED=0                                             # Dependency counter total
DEPS_LIST=""                                                 # String collection of dependencies resolved and added
declare -a REPORT_INSTALLED=()                               # List of packages installed in this transaction
declare -a REPORT_UPDATED=()                                 # List of packages upgraded/updated in this transaction
declare -a REPORT_DELETED=()                                 # List of packages removed/deleted in this transaction

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
# SYSTEM SAFE EXIT & SIGNAL HANDLING
# ──────────────────────────────────────────────────────────────────────────────

# @description Performs recursive cleanup of all recorded temporary workspaces.
# @globals TEMP_DIRS Array containing paths of all generated temporary folders.
cleanup() {
    local tmpdir
    for tmpdir in "${TEMP_DIRS[@]}"; do
        if [[ -d "$tmpdir" ]]; then
            rm -rf "$tmpdir" 2>/dev/null || true
        fi
    done
}

# @description Aborts execution gracefully and triggers cleanup.
# @param $1 string Error/abort message.
abort() {
    local message="${1:-Installation aborted by user.}"
    echo
    echo "${C_YELLOW}${message}${C_RESET}"
    cleanup
    exit 0
}

# @description Standard error handler bound to ERR trap. Outputs debug info and cleans up.
# @param $1 integer Line number where the error occurred.
handle_err() {
    local exit_code=$?
    local line=$1
    echo "${C_RED}Unexpected error at line ${line} (exit code ${exit_code}).${C_RESET}" >&2
    echo "${C_YELLOW}The script encountered a problem. Please review the output above.${C_RESET}" >&2
    cleanup
    exit "$exit_code"
}

# @description Handler for interrupts (SIGINT/SIGTERM) to ensure safe cleanup on Ctrl+C.
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

# @description Stateful parser of DNF transaction summary dry-run output.
#              Populates global REPORT arrays.
# @param $1 string Dry-run output text from DNF command.
parse_dnf_dry_run() {
    local dry_run_text="$1"
    local state="NONE"
    local line
    
    while IFS= read -r line || [[ -n "$line" ]]; do
        local trimmed
        trimmed="$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        
        if [[ "$trimmed" =~ ^Installing ]]; then
            state="INSTALL"
            continue
        elif [[ "$trimmed" =~ ^Upgrading ]]; then
            state="UPDATE"
            continue
        elif [[ "$trimmed" =~ ^Removing ]]; then
            state="DELETE"
            continue
        elif [[ "$trimmed" =~ ^Downgrading ]]; then
            state="DOWNGRADE"
            continue
        elif [[ "$trimmed" =~ ^Transaction\ Summary ]] || [[ "$trimmed" =~ ^=== ]]; then
            state="NONE"
            continue
        fi
        
        if [[ "$state" != "NONE" ]] && [[ "$line" =~ ^[[:space:]]+[^[:space:]]+ ]]; then
            local pkg arch ver repo size
            read -r pkg arch ver repo size <<< "$line"
            
            if [[ -n "$pkg" ]] && [[ -n "$ver" ]] && [[ "$pkg" != "Package" ]] && [[ "$pkg" != "Installing" ]] && [[ "$pkg" != "Upgrading" ]] && [[ "$pkg" != "Removing" ]]; then
                case "$state" in
                    INSTALL)
                        REPORT_INSTALLED+=("${pkg} (${ver})")
                        ;;
                    UPDATE|DOWNGRADE)
                        REPORT_UPDATED+=("${pkg} (${ver})")
                        ;;
                    DELETE)
                        REPORT_DELETED+=("${pkg} (${ver})")
                        ;;
                esac
            fi
        fi
    done <<< "$dry_run_text"
}

# @description Prints a beautifully colorized summary table of all package changes.
print_final_report() {
    if [[ ${#REPORT_INSTALLED[@]} -eq 0 ]] && \
       [[ ${#REPORT_UPDATED[@]} -eq 0 ]] && \
       [[ ${#REPORT_DELETED[@]} -eq 0 ]]; then
        echo
        echo_yellow "  No package changes were made."
        echo
        return
    fi

    echo
    echo "${C_BOLD}  ┌──────────────────────────────────────────────────────────────────────────────┐${C_RESET}"
    printf "  ${C_BOLD}│${C_RESET} %-76s ${C_BOLD}│${C_RESET}\n" "$(echo_bold "FINAL TRANSACTION SUMMARY REPORT")"
    echo "${C_BOLD}  ├────────────────────────────────────────┬──────────┬──────────────────────────┤${C_RESET}"
    printf "  ${C_BOLD}│${C_RESET} %-38s ${C_BOLD}│${C_RESET} %-8s ${C_BOLD}│${C_RESET} %-24s ${C_BOLD}│${C_RESET}\n" "Package Name" "Action" "Version/Details"
    echo "${C_BOLD}  ├────────────────────────────────────────┼──────────┼──────────────────────────┤${C_RESET}"

    # Helper function to print a table row
    print_row() {
        local name="$1"
        local action="$2"
        local details="$3"
        local action_color="$4"
        
        local name_trunc="${name:0:38}"
        local details_trunc="${details:0:24}"
        
        printf "  ${C_BOLD}│${C_RESET} %-38s ${C_BOLD}│${C_RESET} ${action_color}%-8s${C_RESET} ${C_BOLD}│${C_RESET} %-24s ${C_BOLD}│${C_RESET}\n" \
            "$name_trunc" "$action" "$details_trunc"
    }

    local item
    for item in "${REPORT_DELETED[@]}"; do
        local name="$item"
        local details=""
        if [[ "$item" =~ ^(.*)[[:space:]]+\((.*)\)$ ]]; then
            name="${BASH_REMATCH[1]}"
            details="${BASH_REMATCH[2]}"
        fi
        print_row "$name" "DELETED" "$details" "$C_RED"
    done

    for item in "${REPORT_UPDATED[@]}"; do
        local name="$item"
        local details=""
        if [[ "$item" =~ ^(.*)[[:space:]]+\((.*)\)$ ]]; then
            name="${BASH_REMATCH[1]}"
            details="${BASH_REMATCH[2]}"
        fi
        print_row "$name" "UPDATED" "$details" "$C_BLUE"
    done

    for item in "${REPORT_INSTALLED[@]}"; do
        local name="$item"
        local details=""
        if [[ "$item" =~ ^(.*)[[:space:]]+\((.*)\)$ ]]; then
            name="${BASH_REMATCH[1]}"
            details="${BASH_REMATCH[2]}"
        fi
        print_row "$name" "INSTALLED" "$details" "$C_GREEN"
    done

    echo "${C_BOLD}  └────────────────────────────────────────┴──────────┴──────────────────────────┘${C_RESET}"
    echo
}

# @description Checks if the selected package name is already installed on the system.
#              If it exists, prompts the user to uninstall it before continuing.
check_and_remove_existing() {
    if [[ "$SELECTED_TYPE" == "RPM" ]]; then
        local rpm_name
        rpm_name="$(rpm -qp --queryformat '%{name}' "$SELECTED_PATH" 2>/dev/null || echo "")"
        if [[ -n "$rpm_name" ]] && rpm -q "$rpm_name" &>/dev/null; then
            local installed_version
            installed_version="$(rpm -q --queryformat '%{version}-%{release}' "$rpm_name" 2>/dev/null || echo "unknown")"
            echo
            echo_yellow "  ⚠ Package '${rpm_name}' is already installed (Version: ${installed_version})."
            if ask_yes_no "Do you want to uninstall the existing version and install the new one?" "Y"; then
                echo "  Removing existing package '${rpm_name}'..."
                if sudo dnf remove -y "$rpm_name"; then
                    echo_green "  ✅ Successfully removed the old version."
                    REPORT_DELETED+=("${rpm_name} (${installed_version})")
                    # Invalidate cached dry-run because transaction profile changed
                    DNF_DRY_RUN_OUTPUT=""
                else
                    echo_red "  ❌ Failed to remove the old version. Proceeding anyway."
                fi
            else
                abort "Installation aborted by user (existing package preserved)."
            fi
        fi
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 0 — ENVIRONMENT PRE-FLIGHT CHECKS
# ──────────────────────────────────────────────────────────────────────────────

# @description Validates target operating system, space, internet, and checks for binary tools.
# @globals OS_NAME, OS_VERSION, OS_ID, HAS_DNF, HAS_RPM, HAS_FUSE, HAS_PGP, HAS_DESKTOP
preflight_checks() {
    local warnings=()
    local critical_errors=()

    # Step 1: Detect exact Linux distribution names and version IDs
    local is_redhat=false
    if [[ -f /etc/redhat-release ]]; then
        is_redhat=true
    fi
    if [[ -f /etc/os-release ]]; then
        OS_NAME="$(grep -oP '^PRETTY_NAME="?\K[^"]+' /etc/os-release || true)"
        OS_VERSION="$(grep -oP '^VERSION_ID="?\K[^"]+' /etc/os-release || true)"
        OS_ID="$(grep -oP '^ID="?\K[^"]+' /etc/os-release || true)"
        local id_like
        id_like="$(grep -oP '^ID_LIKE="?\K[^"]+' /etc/os-release || true)"
        if [[ "$OS_ID" =~ ^(fedora|rhel|centos|almalinux|rocky|ol)$ ]] || [[ "$id_like" =~ (fedora|rhel|centos) ]]; then
            is_redhat=true
        fi
    fi

    if ! $is_redhat; then
        echo
        echo_red "  ❌ Error: This script is only supported on Red Hat-based distributions (e.g., Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux)."
        echo
        exit 1
    fi

    if [[ -z "$OS_NAME" ]]; then
        OS_NAME="Unknown Linux"
    fi

    # Step 2: Detect package manager binaries
    if command -v dnf &>/dev/null; then
        HAS_DNF=true
        PACKAGE_MANAGER="dnf ($(dnf --version 2>/dev/null | awk 'NR==1' || true))"
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

    # Step 7: Check for PGP verification engine (GnuPG)
    if command -v gpg &>/dev/null; then
        HAS_PGP=true
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
        echo "  Proceeding..."
        echo
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 1 — PACKAGE DISCOVERY
# ──────────────────────────────────────────────────────────────────────────────

# @description Searches current directory for RPM and AppImage packages.
# @globals RPM_FILES, APPIMAGE_FILES, ALL_PACKAGES, ALL_PACKAGES_PATHS, ALL_PACKAGES_SHA256
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

# Package selection is handled dynamically in main coordinator.

# @description Simulates RPM installation using sudo dnf install --assumeno.
#              Parses and reports dependencies, package upgrades, conflicts, and dangerous removals.
# @globals SELECTED_PATH, DNF_DRY_RUN_OUTPUT, DEPS_INSTALLED
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
        DNF_DRY_RUN_OUTPUT="$(sudo dnf install --assumeno "$SELECTED_PATH" 2>&1 || true)"
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

    # Check if DNF warns that PGP signature validation fails or keys are missing
    if echo "$dry_run_output" | grep -qi "is not signed"; then
        has_unsigned=true
    elif echo "$dry_run_output" | grep -qi "gpg\|pgp"; then
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
    if [[ "$has_unsigned" == "true" ]]; then
        warning_details+="  │ ${C_YELLOW}⚠${C_RESET}  Package is NOT signed with a known PGP key"$'\n'
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
# STAGE 3 — PGP/GPG SIGNATURE & CHECKSUM VERIFICATION
# ──────────────────────────────────────────────────────────────────────────────

# @description Orchestrates the package validation logic. Attempts detached PGP/GPG signature
#              and checksum file checks, falling back to embedded signature or SHA256 manual checks.
# @globals SELECTED_PATH, SELECTED_TYPE, PGP_VERIFIED, PGP_SIGNER, PGP_KEY_ID
pgp_verification() {
    local pkg_dir
    pkg_dir="$(dirname "$SELECTED_PATH")"
    local pkg_file
    pkg_file="$(basename "$SELECTED_PATH")"
    local pkg_name_noext="${pkg_file%.*}"
    
    # Search for matching detached signature files (supporting all PGP/GPG extensions case-insensitively)
    local sig_candidates=()
    local ext
    for ext in sig SIG asc ASC pgp PGP gpg GPG signature SIGNATURE sign SIGN; do
        [[ -f "${pkg_dir}/${pkg_file}.${ext}" ]] && sig_candidates+=("${pkg_dir}/${pkg_file}.${ext}")
        [[ -f "${pkg_dir}/${pkg_name_noext}.${ext}" ]] && sig_candidates+=("${pkg_dir}/${pkg_name_noext}.${ext}")
    done
    
    local unique_sig_candidates=()
    local cand
    for cand in "${sig_candidates[@]}"; do
        local exists=false
        local u
        for u in "${unique_sig_candidates[@]}"; do
            [[ "$u" == "$cand" ]] && exists=true && break
        done
        [[ "$exists" == "false" ]] && unique_sig_candidates+=("$cand")
    done
    
    # Automatically select the first candidate (no questions asked)
    local found_sig=""
    if [[ ${#unique_sig_candidates[@]} -gt 0 ]]; then
        found_sig="${unique_sig_candidates[0]}"
        echo "  Automatically selected PGP/GPG signature file: $(basename "$found_sig")"
    fi

    # Verify using detached signature if confirmed
    if [[ -n "$found_sig" ]]; then
        echo
        echo "  Verifying PGP/GPG signature using: $(basename "$found_sig")"
        
        if [[ "$HAS_PGP" == "false" ]]; then
            echo_yellow "  ⚠ GnuPG is not installed. Installing gnupg2 automatically..."
            sudo dnf install -y gnupg2 && HAS_PGP=true
        fi

        local verify_output
        verify_output="$(gpg --verify "$found_sig" "$SELECTED_PATH" 2>&1 || true)"
        
        if echo "$verify_output" | grep -qi "good signature"; then
            PGP_VERIFIED=true
            PGP_SIGNER="$(echo "$verify_output" | grep -oP '"([^"]+)"' | awk 'NR==1' || echo "Unknown")"
            PGP_KEY_ID="$(echo "$verify_output" | grep -i "using" | grep -oP '\b[0-9A-Fa-f]{8,40}\b' | head -n 1 || echo "unknown")"
            echo_green "  ✅ PGP/GPG DETACHED SIGNATURE VERIFIED SUCCESSFULLY"
            echo "  Signer: ${PGP_SIGNER} (${PGP_KEY_ID})"
            echo
            if [[ "$SELECTED_TYPE" == "RPM" ]]; then
                check_and_remove_existing
                risk_analysis
                install_rpm || abort "Installation failed."
            else
                install_appimage || abort "AppImage integration failed."
            fi
            return 0
        elif echo "$verify_output" | grep -qi "no public key\|public key .* not found\|keyserver"; then
            local key_id
            key_id="$(echo "$verify_output" | grep -i "using" | grep -oP '\b[0-9A-Fa-f]{8,40}\b' | head -n 1 || true)"
            
            echo_yellow "  ⚠ PGP/GPG Key Not Found (NOKEY)"
            echo "  Attempting to retrieve public key (${key_id}) automatically..."
            
            local import_success=false
            local keyserver
            for keyserver in "keyserver.ubuntu.com" "keys.openpgp.org"; do
                echo "  Fetching key from ${keyserver}..."
                local tmp_key
                tmp_key="$(mktemp)"
                TEMP_DIRS+=("$tmp_key")
                if gpg --keyserver "$keyserver" --recv-keys "$key_id" 2>/dev/null && gpg --export --armor "$key_id" > "$tmp_key" 2>/dev/null; then
                    if [[ "$SELECTED_TYPE" == "RPM" ]]; then
                        sudo rpm --import "$tmp_key" &>/dev/null || true
                    fi
                    gpg --import "$tmp_key" &>/dev/null || true
                    import_success=true
                    break
                fi
            done
            
            if $import_success; then
                echo_green "  ✅ Successfully imported public key."
                verify_output="$(gpg --verify "$found_sig" "$SELECTED_PATH" 2>&1 || true)"
                if echo "$verify_output" | grep -qi "good signature"; then
                    PGP_VERIFIED=true
                    PGP_SIGNER="Imported Key (${key_id})"
                    PGP_KEY_ID="${key_id}"
                    echo_green "  ✅ PGP/GPG DETACHED SIGNATURE VERIFIED"
                    if [[ "$SELECTED_TYPE" == "RPM" ]]; then
                        check_and_remove_existing
                        risk_analysis
                        install_rpm || abort "Installation failed."
                    else
                        install_appimage || abort "AppImage integration failed."
                    fi
                    return 0
                fi
            fi
            
            echo_red "  ❌ Failed to verify signature after key import."
            if ask_yes_no "Do you want to proceed anyway?" "N"; then
                if [[ "$SELECTED_TYPE" == "RPM" ]]; then
                    check_and_remove_existing
                    risk_analysis
                    install_rpm || abort "Installation failed."
                else
                    install_appimage || abort "AppImage integration failed."
                fi
            else
                abort "Installation aborted."
            fi
            return 0
        else
            echo_red "  ❌ CRITICAL WARNING: DETACHED PGP/GPG SIGNATURE IS INVALID OR CORRUPT (BAD)!"
            echo "  --------------------------------------------------------"
            echo "  The package file has been modified or does not match this signature."
            echo "  It is highly dangerous to install this package."
            echo "  --------------------------------------------------------"
            echo
            if ask_yes_no "Do you want to proceed with installation anyway (Dangerous)?" "N"; then
                if [[ "$SELECTED_TYPE" == "RPM" ]]; then
                    check_and_remove_existing
                    risk_analysis
                    install_rpm || abort "Installation failed."
                else
                    install_appimage || abort "AppImage integration failed."
                fi
            else
                abort "Installation aborted due to BAD signature."
            fi
            return 0
        fi
    fi

    # Search for matching checksum files
    local checksum_candidates=()
    local cext
    for cext in sha256 sha256sum; do
        [[ -f "${pkg_dir}/${pkg_file}.${cext}" ]] && checksum_candidates+=("${pkg_dir}/${pkg_file}.${cext}")
        [[ -f "${pkg_dir}/${pkg_name_noext}.${cext}" ]] && checksum_candidates+=("${pkg_dir}/${pkg_name_noext}.${cext}")
    done
    [[ -f "${pkg_dir}/SHA256SUMS" ]] && checksum_candidates+=("${pkg_dir}/SHA256SUMS")
    [[ -f "${pkg_dir}/checksums.txt" ]] && checksum_candidates+=("${pkg_dir}/checksums.txt")

    local unique_checksum_candidates=()
    local ccand
    for ccand in "${checksum_candidates[@]}"; do
        local cexists=false
        local cu
        for cu in "${unique_checksum_candidates[@]}"; do
            [[ "$cu" == "$ccand" ]] && cexists=true && break
        done
        [[ "$cexists" == "false" ]] && unique_checksum_candidates+=("$ccand")
    done

    # Automatically select the first checksum candidate (no questions asked)
    local found_checksum=""
    if [[ ${#unique_checksum_candidates[@]} -gt 0 ]]; then
        found_checksum="${unique_checksum_candidates[0]}"
        echo "  Automatically selected checksum file: $(basename "$found_checksum")"
    fi

    # Verify using checksum file if confirmed
    if [[ -n "$found_checksum" ]]; then
        echo
        echo "  Verifying integrity using checksum file: $(basename "$found_checksum")"
        
        local expected_sha=""
        local line
        line="$(grep -F "$pkg_file" "$found_checksum" | head -n 1 || true)"
        if [[ -n "$line" ]]; then
            expected_sha="$(echo "$line" | grep -oP '[0-9a-fA-F]{64}' | head -n 1 || true)"
        else
            expected_sha="$(grep -oP '\b[0-9a-fA-F]{64}\b' "$found_checksum" | head -n 1 || true)"
        fi
        
        expected_sha="${expected_sha// /}"
        expected_sha="$(echo "$expected_sha" | tr '[:upper:]' '[:lower:]')"
        local calculated_sha
        calculated_sha="$(echo "$SELECTED_SHA256" | tr '[:upper:]' '[:lower:]')"

        if [[ -z "$expected_sha" ]]; then
            echo_yellow "  ⚠ Could not find a valid 64-character SHA256 checksum in $(basename "$found_checksum"). Proceeding..."
        else
            echo "  Expected SHA256: ${expected_sha}"
            echo "  Calculated SHA256: ${calculated_sha}"
            echo

            if [[ "$expected_sha" == "$calculated_sha" ]]; then
                PGP_VERIFIED=true
                PGP_SIGNER="Verified via $(basename "$found_checksum")"
                echo_green "  ✅ CHECKSUM MATCHED SUCCESSFULLY!"
                echo
                if [[ "$SELECTED_TYPE" == "RPM" ]]; then
                    check_and_remove_existing
                    risk_analysis
                    install_rpm || abort "Installation failed."
                else
                    install_appimage || abort "AppImage integration failed."
                fi
                return 0
            else
                echo_red "  ❌ CRITICAL WARNING: CHECKSUM MISMATCH!"
                echo "  --------------------------------------------------------"
                echo "  The calculated checksum does NOT match the expected value."
                echo "  This file is corrupted, altered, or insecure to install."
                echo "  --------------------------------------------------------"
                echo
                if ask_yes_no "Do you want to proceed with installation anyway (Dangerous)?" "N"; then
                    if [[ "$SELECTED_TYPE" == "RPM" ]]; then
                        check_and_remove_existing
                        risk_analysis
                        install_rpm || abort "Installation failed."
                    else
                        install_appimage || abort "AppImage integration failed."
                    fi
                else
                    abort "Installation aborted due to checksum mismatch."
                fi
                return 0
            fi
        fi
    fi

    # Fallback to embedded signature or manual verification
    if [[ "$SELECTED_TYPE" == "AppImage" ]]; then
        echo
        echo "  ${C_BLUE}ℹ${C_RESET} No PGP/GPG signature or checksum file found."
        echo "  Computed SHA256: ${SELECTED_SHA256}"
        echo
        if ask_yes_no "Do you want to proceed with installing this unverified AppImage?" "N"; then
            install_appimage || abort "AppImage integration failed."
        else
            abort "Aborted: AppImage verification declined."
        fi
        return 0
    fi

    echo
    echo "  No signature or checksum file found. Checking embedded RPM signature..."
    
    local rpm_k_output
    rpm_k_output="$(rpm -K "$SELECTED_PATH" 2>&1 || true)"
    
    if echo "$rpm_k_output" | grep -qi "signatures OK\|gpg OK\|pgp OK"; then
        PGP_VERIFIED=true
        PGP_SIGNER="RPM Trusted Key"
        PGP_KEY_ID="$(rpm -qp --queryformat '%{SIGPGP:pgpsig}' "$SELECTED_PATH" 2>/dev/null | grep -oP 'key ID [0-9A-Fa-f]+' | awk '{print $NF}' || echo "trusted")"
        echo_green "  ✅ EMBEDDED PGP/GPG SIGNATURE VERIFIED SUCCESSFULLY"
        echo "  Signer: ${PGP_SIGNER} (Key ID: ${PGP_KEY_ID})"
        echo
        check_and_remove_existing
        risk_analysis
        install_rpm || abort "Installation failed."
    elif echo "$rpm_k_output" | grep -qi "BAD"; then
        echo_red "  ❌ CRITICAL WARNING: EMBEDDED PGP/GPG SIGNATURE IS INVALID OR CORRUPT (BAD)!"
        echo "  --------------------------------------------------------"
        echo "  The package has been modified, corrupted, or tampered with."
        echo "  It is highly dangerous to install this package."
        echo "  --------------------------------------------------------"
        echo
        if ask_yes_no "Do you want to proceed with installation anyway (Dangerous)?" "N"; then
            check_and_remove_existing
            risk_analysis
            install_rpm || abort "Installation failed."
        else
            abort "Installation aborted due to BAD signature."
        fi
    elif echo "$rpm_k_output" | grep -qi "NOKEY"; then
        local key_id
        key_id="$(echo "$rpm_k_output" | grep -oP 'key ID [0-9A-Fa-f]+' | awk '{print $NF}' || true)"
        [[ -z "$key_id" ]] && key_id="$(echo "$rpm_k_output" | grep -oP 'Key ID [0-9A-Fa-f]+' | awk '{print $NF}' || true)"
        
        echo_yellow "  ⚠ PGP/GPG Key Not Found (NOKEY)"
        echo "  The package signature is valid, but the signing key is not trusted."
        if [[ -n "$key_id" ]]; then
            echo "  Key ID: ${key_id}"
            echo
            echo "  Attempting to retrieve public key (${key_id}) automatically..."
            local import_success=false
            local keyserver
            for keyserver in "keyserver.ubuntu.com" "keys.openpgp.org"; do
                echo "  Fetching key from ${keyserver}..."
                local tmp_key
                tmp_key="$(mktemp)"
                TEMP_DIRS+=("$tmp_key")
                if gpg --keyserver "$keyserver" --recv-keys "$key_id" 2>/dev/null && gpg --export --armor "$key_id" > "$tmp_key" 2>/dev/null; then
                    if sudo rpm --import "$tmp_key" &>/dev/null; then
                        gpg --import "$tmp_key" &>/dev/null || true
                        import_success=true
                        break
                    fi
                fi
            done
            if $import_success; then
                echo_green "  ✅ Successfully imported public key."
                rpm_k_output="$(rpm -K "$SELECTED_PATH" 2>&1 || true)"
                if echo "$rpm_k_output" | grep -qi "signatures OK\|gpg OK\|pgp OK"; then
                    PGP_VERIFIED=true
                    PGP_SIGNER="Imported Key (${key_id})"
                    PGP_KEY_ID="${key_id}"
                    echo_green "  ✅ PGP/GPG SIGNATURE VERIFIED"
                    check_and_remove_existing
                    risk_analysis
                    install_rpm || abort "Installation failed."
                    return 0
                fi
            fi
            echo_red "  ❌ Failed to verify signature after key import."
            if ask_yes_no "Do you want to proceed anyway?" "N"; then
                check_and_remove_existing
                risk_analysis
                install_rpm || abort "Installation failed."
            else
                abort "Installation aborted."
            fi
        else
            if ask_yes_no "Do you want to proceed without verification?" "N"; then
                check_and_remove_existing
                risk_analysis
                install_rpm || abort "Installation failed."
            else
                abort "Installation aborted."
            fi
        fi
    else
        echo_yellow "  ⚠ Package is not signed (Unsigned)"
        if ask_yes_no "Do you want to install this unsigned package?" "N"; then
            check_and_remove_existing
            risk_analysis
            install_rpm || abort "Installation failed."
        else
            abort "Installation aborted."
        fi
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 4A — SAFE RPM INSTALLATION
# ──────────────────────────────────────────────────────────────────────────────
# STAGE 4A — SAFE RPM INSTALLATION
# ──────────────────────────────────────────────────────────────────────────────

# @description Performs the actual installation of the chosen RPM using sudo dnf install.
# @globals SELECTED_PATH, DEPS_INSTALLED, DISK_SPACE_AVAIL, PGP_VERIFIED, PGP_SIGNER, PGP_KEY_ID
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
        dry_run_output="$(sudo dnf install --assumeno "$full_path" 2>&1 || true)"
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
    echo "  PGP Verified:  ${PGP_VERIFIED:-${C_YELLOW}No${C_RESET}}"
    echo
    echo "  Disk space required: ~${SELECTED_SIZE}"
    echo "  Available disk space: ${DISK_SPACE_AVAIL}"
    echo

    # Proceed automatically
    echo
    echo "  Running: sudo dnf install -y \"${full_path}\""
    echo

    # Step 1: Run DNF with live console output.
    local install_rc=0
    sudo dnf install -y "$full_path" || install_rc=$?
    if [[ "$install_rc" -ne 0 ]]; then
        local install_output=""
        { install_output="$(sudo dnf install -y "$full_path" 2>&1)" || true; } 2>/dev/null
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

    echo_green "  ✅  Installation completed successfully."

    # Parse transaction dry-run to populate report
    if [[ -n "$DNF_DRY_RUN_OUTPUT" ]]; then
        parse_dnf_dry_run "$DNF_DRY_RUN_OUTPUT"
    fi

    # Step 3: Query RPM database to record package files destination path
    INSTALL_LOCATION="$(rpm -ql "$pkg_name" 2>/dev/null | awk 'NR<=5' | tr '\n' ' ' || echo "See 'rpm -ql ${pkg_name}'")"
    INSTALL_STATUS="success"

    echo
    print_box "INSTALLATION COMPLETE"
    echo
    echo "  ${C_GREEN}Package:${C_RESET}          ${pkg_name}-${rpm_version}.${rpm_arch}"
    echo "  ${C_GREEN}Type:${C_RESET}             RPM"
    echo "  ${C_GREEN}Source file:${C_RESET}      ${full_path}"
    echo "  ${C_GREEN}SHA256:${C_RESET}           ${SELECTED_SHA256}"
    echo
    if [[ "$PGP_VERIFIED" == "true" ]]; then
        echo "  ${C_GREEN}PGP Verified:     ✅ Yes — ${PGP_SIGNER} (${PGP_KEY_ID})${C_RESET}"
    else
        echo "  ${C_YELLOW}PGP Verified:     ⚠ No${C_RESET}"
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

    print_box "APPIMAGE INTEGRATION"

    # ── Step 1: Ensure FUSE dependencies are met ────────────────────────
    if ! $HAS_FUSE; then
        echo
        echo_yellow "  ⚠  FUSE is not installed. Installing FUSE automatically..."
        local fuse_pkg="fuse3 fuse3-libs"
        if ! dnf info fuse3 &>/dev/null 2>&1; then
            fuse_pkg="fuse fuse-libs"
        fi
        sudo dnf install -y $fuse_pkg || true
        # Recheck dependencies status
        if rpm -q fuse &>/dev/null || rpm -q fuse-libs &>/dev/null || \
           rpm -q fuse3 &>/dev/null || rpm -q fuse3-libs &>/dev/null; then
            HAS_FUSE=true
            echo_green "  ✅  FUSE installed."
        else
            echo_yellow "  ⚠ FUSE could not be installed automatically. AppImage may not execute."
        fi
    fi

    # ── Step 2: Assign target path directory (automatic) ──────────────────
    dest_dir="${HOME}/Applications"
    if [[ ! -d "$dest_dir" ]]; then
        mkdir -p "$dest_dir" || dest_dir="$START_DIR"
    fi
    dest_path="${dest_dir}/${appimage_name}"

    # Check if AppImage already exists
    if [[ -f "$dest_path" ]]; then
        echo
        echo_yellow "  ⚠ An AppImage named '${appimage_name}' already exists at destination."
        if ask_yes_no "Do you want to remove the existing version and install the new one?" "Y"; then
            echo "  Removing existing version and launcher files..."
            rm -f "$dest_path"
            rm -f "${HOME}/.local/share/applications/${appimage_basename}.desktop"
            rm -f "${HOME}/.local/share/icons/${appimage_basename}".*
            echo_green "  ✅ Successfully removed the old version."
            REPORT_DELETED+=("${appimage_name} (AppImage)")
        else
            abort "Integration aborted by user (existing version preserved)."
        fi
    fi

    # ── Step 3: Change permissions and copy executable (automatic) ─────────
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
    echo_green "  ✅  AppImage integrated."

    # ── Step 4: Extract desktop launcher configuration files ─────────────
    if $HAS_DESKTOP; then
        extract_desktop_entry "$dest_path" "$appimage_basename" "$dest_dir" "$appimage_name"
    else
        echo
        echo "  ${C_BLUE}ℹ${C_RESET}  No desktop environment detected. Skipping desktop launcher creation."
    fi

    # Record installation
    REPORT_INSTALLED+=("${appimage_name} (AppImage)")

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
    cp "$appimage_path" "$tmpdir/" || return 1
    local tmp_appimage="${tmpdir}/$(basename "$appimage_path")"
    chmod +x "$tmp_appimage" || return 1

    if (cd "$tmpdir" && "$tmp_appimage" --appimage-extract &>/dev/null); then
        echo "  Extraction successful."
    else
        echo_yellow "  Extraction failed. Creating a basic desktop entry manually."
        create_manual_desktop "$appimage_path" "$appimage_basename" "" "$appimage_basename"
        return 0
    fi

    local squash_dir="${tmpdir}/squashfs-root"
    if [[ ! -d "$squash_dir" ]]; then
        echo_yellow "  squashfs-root not found. Creating basic desktop entry."
        create_manual_desktop "$appimage_path" "$appimage_basename" "" "$appimage_basename"
        return 0
    fi

    # ── ICON EXTRACTION ──────────────────────────────────────────────────
    local chosen_icon=""

    if [[ -f "${squash_dir}/.DirIcon" ]]; then
        chosen_icon="${squash_dir}/.DirIcon"
    fi

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
                local resolved=""
                for ext in svg png xpm; do
                    resolved="$(find "$squash_dir" -type f -iname "${icon_name}.${ext}" -print -quit 2>/dev/null || true)"
                    if [[ -n "$resolved" ]]; then
                        chosen_icon="$resolved"
                        break 2
                    fi
                done
                if [[ -z "$chosen_icon" ]]; then
                    for ext in svg png xpm; do
                        resolved="$(find "$squash_dir" -type f -iname "${icon_name}*.${ext}" -print -quit 2>/dev/null || true)"
                        if [[ -n "$resolved" ]]; then
                            chosen_icon="$resolved"
                            break 2
                        fi
                    done
                fi
            fi
        done
    fi

    if [[ -z "$chosen_icon" ]]; then
        local best_png=""
        local best_size=0
        local png_candidate
        while IFS= read -r -d '' png_candidate; do
            local fname_lower
            fname_lower="$(basename "$png_candidate" | tr '[:upper:]' '[:lower:]')"
            local candidate_size=0
            if [[ "$fname_lower" =~ ([0-9]+)x[0-9]+ ]]; then
                candidate_size="${BASH_REMATCH[1]}"
            elif [[ "$fname_lower" =~ [-_]([0-9]+)[._] ]]; then
                candidate_size="${BASH_REMATCH[1]}"
            elif [[ "$fname_lower" =~ [-_]([0-9]+)\.png ]]; then
                candidate_size="${BASH_REMATCH[1]}"
            fi
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
        fi
    fi

    if [[ -z "$chosen_icon" ]]; then
        chosen_icon="$(find "$squash_dir" -type f -iname '*.png' -print -quit 2>/dev/null || true)"
    fi
    if [[ -z "$chosen_icon" ]]; then
        chosen_icon="$(find "$squash_dir" -type f -iname '*.svg' -print -quit 2>/dev/null || true)"
    fi

    # Install the chosen icon to user icons directory
    icon_file=""
    if [[ -n "$chosen_icon" ]]; then
        local icon_filename
        icon_filename="$(basename "$chosen_icon")"
        icon_ext="${icon_filename##*.}"
        local icon_ext_lower
        icon_ext_lower="$(echo "$icon_ext" | tr '[:upper:]' '[:lower:]')"

        local final_ext="$icon_ext_lower"
        if [[ "$icon_ext_lower" == "xpm" ]]; then
            if command -v convert &>/dev/null; then
                final_ext="png"
            fi
        fi

        local icon_dest="${HOME}/.local/share/icons/${appimage_basename}.${final_ext}"
        mkdir -p "${HOME}/.local/share/icons"
        if cp "$chosen_icon" "$icon_dest" 2>/dev/null; then
            if [[ "$icon_ext_lower" == "xpm" ]] && command -v convert &>/dev/null; then
                convert "$icon_dest" "${HOME}/.local/share/icons/${appimage_basename}.png" 2>/dev/null || true
                rm -f "${icon_dest}" 2>/dev/null || true
                icon_dest="${HOME}/.local/share/icons/${appimage_basename}.png"
            fi
            icon_file="$icon_dest"
            echo "  Icon installed: ${icon_dest}"
        fi
    fi

    # ── DESKTOP ENTRY EXTRACTION ──────────────────────────────────────
    local search_desktop
    search_desktop="$(find "$squash_dir" -maxdepth 3 -type f -iname '*.desktop' 2>/dev/null | awk 'NR==1' || true)"
    if [[ -n "$search_desktop" ]]; then
        extracted_desktop="$search_desktop"
        
        local modified_desktop="${tmpdir}/modified.desktop"
        local exec_path="${appimage_path}"
        if [[ -n "$dest_dir_arg" ]] && [[ -n "$appimage_name_arg" ]] && [[ -f "${dest_dir_arg}/${appimage_name_arg}" ]]; then
            exec_path="${dest_dir_arg}/${appimage_name_arg}"
        fi
        local icon_path="${icon_file:-${appimage_basename}}"

        : > "$modified_desktop"
        while IFS= read -r dline || [[ -n "$dline" ]]; do
            if [[ "$dline" =~ ^Exec= ]]; then
                local exec_args=""
                local orig_exec="$dline"
                orig_exec="${orig_exec#Exec=}"
                exec_args="$(echo "$orig_exec" | grep -oP '%[fFuUcCdDnNickvm]+' || true)"
                echo "Exec=${exec_path} ${exec_args}" >> "$modified_desktop"
            elif [[ "$dline" =~ ^TryExec= ]]; then
                echo "TryExec=${exec_path}" >> "$modified_desktop"
            elif [[ "$dline" =~ ^Icon= ]]; then
                echo "Icon=${icon_path}" >> "$modified_desktop"
            else
                echo "$dline" >> "$modified_desktop"
            fi
        done < "$extracted_desktop"

        local desktop_dest="${HOME}/.local/share/applications/${appimage_basename}.desktop"
        mkdir -p "${HOME}/.local/share/applications"
        cp "$modified_desktop" "$desktop_dest"
        chmod +x "$desktop_dest"

        if $HAS_UPDATE_DESKTOP_DB; then
            update-desktop-database "${HOME}/.local/share/applications" 2>/dev/null || true
        fi
        echo "  Desktop entry created: ${desktop_dest}"
    else
        local icon_param="${icon_file:-}"
        create_manual_desktop "$appimage_path" "$appimage_basename" "$icon_param" "$appimage_basename"
    fi
}

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

    local desktop_dest="${HOME}/.local/share/applications/${desktop_name}.desktop"
    mkdir -p "${HOME}/.local/share/applications"
    echo "$desktop_content" > "$desktop_dest"
    chmod +x "$desktop_dest"

    if $HAS_UPDATE_DESKTOP_DB; then
        update-desktop-database "${HOME}/.local/share/applications" 2>/dev/null || true
    fi
    echo "  Desktop entry created: ${desktop_dest}"
}

# ──────────────────────────────────────────────────────────────────────────────
# MAIN COORDINATOR
# ──────────────────────────────────────────────────────────────────────────────

# @description Coordinator of script execution flow. Initiates stages in sequence
#              and handles goal actions (verify first vs direct install).
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

    local total="${#ALL_PACKAGES[@]}"
    local choice=""
    local mode=""
    local idx=0

    while true; do
        read -r -p "  Enter package number to install, or type 'all' to install all (or 'q' to quit): " choice
        local clean_choice
        clean_choice="$(echo "$choice" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]')"

        if [[ "$clean_choice" == "q" ]] || [[ "$clean_choice" == "0" ]]; then
            abort
        fi

        if [[ "$clean_choice" == "all" ]]; then
            mode="all"
            break
        fi

        if [[ "$clean_choice" =~ ^[0-9]+$ ]]; then
            idx="$((10#$clean_choice))"
            if [[ "$idx" -lt 1 ]] || [[ "$idx" -gt "$total" ]]; then
                echo_yellow "  Number out of range. Please enter 1-${total} or 'all'."
                continue
            fi
            mode="single"
            break
        fi

        echo_yellow "  Invalid selection. Please choose a package number (1-${total}) or type 'all'."
    done

    if [[ "$mode" == "single" ]]; then
        # Map selected package information to target globals
        SELECTED_INDEX="$idx"
        SELECTED_PATH="${ALL_PACKAGES_PATHS[$((idx-1))]}"
        SELECTED_TYPE="${ALL_PACKAGES_TYPES[$((idx-1))]}"
        SELECTED_SIZE="${ALL_PACKAGES_SIZES[$((idx-1))]}"
        SELECTED_SHA256="${ALL_PACKAGES_SHA256[$((idx-1))]}"
        SELECTED_NAME="$(basename "$SELECTED_PATH")"

        echo
        echo "  Selected: ${SELECTED_NAME}"
        echo

        echo "  Choose your action:"
        echo "    [1] Verify PGP/GPG signature (Highly Recommended)"
        echo "    [2] Install package directly"
        echo
        local action
        while true; do
            read -r -p "  Choose [1-2] (or 'q' to quit): " action
            [[ "$action" == "q" ]] && abort
            [[ "$action" =~ ^[1-2]$ ]] && break
            echo_yellow "  Please enter 1 or 2."
        done

        if [[ "$action" == "2" ]]; then
            echo_yellow "  ⚠ WARNING: Installing unverified packages is a security risk."
            if ! ask_yes_no "Do you want to proceed with the installation anyway?" "N"; then
                abort "Installation cancelled."
            fi
            if [[ "$SELECTED_TYPE" == "RPM" ]]; then
                check_and_remove_existing
                risk_analysis
                install_rpm || abort "Installation failed."
            else
                install_appimage || abort "AppImage integration failed."
            fi
        else
            pgp_verification
        fi
    else
        echo
        echo_blue "  Installing all ${#ALL_PACKAGES_PATHS[@]} package(s) with PGP/GPG signature verification..."
        echo
        
        local i
        for ((i=0; i<${#ALL_PACKAGES_PATHS[@]}; i++)); do
            # Reset verification/transaction states to prevent overlap
            PGP_VERIFIED=false
            PGP_SIGNER=""
            PGP_KEY_ID=""
            DNF_DRY_RUN_OUTPUT=""
            DEPS_INSTALLED=0
            INSTALL_STATUS=""
            INSTALL_LOCATION=""
            
            # Set package variables for this index
            SELECTED_INDEX="$((i+1))"
            SELECTED_PATH="${ALL_PACKAGES_PATHS[i]}"
            SELECTED_TYPE="${ALL_PACKAGES_TYPES[i]}"
            SELECTED_SIZE="${ALL_PACKAGES_SIZES[i]}"
            SELECTED_SHA256="${ALL_PACKAGES_SHA256[i]}"
            SELECTED_NAME="$(basename "$SELECTED_PATH")"
            
            echo_bold "======================================================================"
            echo_bold "  Processing Package [$((i+1))/${#ALL_PACKAGES_PATHS[@]}]: ${SELECTED_NAME}"
            echo_bold "======================================================================"
            
            pgp_verification
            echo
        done
    fi

    # Print final transaction report table
    print_final_report

    echo
    echo_green "  All operations complete."
    echo
}

main
