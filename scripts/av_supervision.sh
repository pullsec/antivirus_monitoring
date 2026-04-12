#!/usr/bin/env bash

######################################
# Name: av_supervision.sh
# Description:
#   Antivirus supervision script used by Centreon.
#
#   This script performs:
#     - HTTP checks for AV definitions
#     - Local parsing of AV engine MANIFEST files
#     - Threshold evaluation (warning / critical)
#     - Output formatting for Centreon (stdout + exit code)
#
# Architecture:
#   AV Server → SSH (jump) → SNMP → Poller → Centreon
#
# Notes:
#   - Designed for segmented environments (no direct access)
#   - Output must follow Nagios/Centreon plugin format
#   - Exit code is critical (message is secondary)
#
# Environment:
#   Debian / Ubuntu
######################################

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

#######################################
# Centreon return codes
#######################################
# IMPORTANT:
# Centreon only uses exit codes to determine status
OK=0
WARNING=1
CRITICAL=2
UNKNOWN=3

#######################################
# Defaults / Configuration
#######################################

# Script identity
SCRIPT_NAME="$(basename "$0")"

# Hostname used to determine mapping (multi-server support)
# fallback to full hostname if short not available
SRV="$(hostname -s 2>/dev/null || hostname)"

# Threshold logic:
# total anomalies = defs + engines
# WARNING: total > WARNING_THRESHOLD
# CRITICAL: total > CRITICAL_THRESHOLD
WARNING_THRESHOLD=0
CRITICAL_THRESHOLD=1

# HTTP configuration
# connect-timeout: fail fast if server unreachable
# max-time: avoid blocking Centreon execution
CURL_TIMEOUT=15

# Base directory where AV engines are stored
# must be adapted per environment
BASE_AV_DIR="/path/path/path/path/path/av"

# Logging directory (optional)
LOG_DIR="/path/path/log"

# Debug flag
# 0 = disabled / 1 = enabled
VERBOSE=0

# Optional override (useful for testing outside prod)
URL_OVERRIDE=""

# HTTP paths (split for reliability)
# 2 sources concatenated for robustness
URL_PATH1="x.x-enka-antivirus/"
URL_PATH2="x.x-enka-antivirus.tar/"

# Keyword used to filter relevant lines
WORD_KEY="enka"

# Special case:
# integration server should never return CRITICAL
# (used for testing / validation environments)
INTEGRATION_SERVER="server4"

# Counters (global to keep debug visibility)
DEF_COUNT=0
ENGINE_COUNT=0

#######################################
# Mapping: server → update URL
#######################################
# avoids hardcoding URL per script instance
# allows multi-environment support
declare -A SERVERS_URLS=(
  ["server1"]="https://path/download/update/"
  ["server2"]="https://path/download/update/"
  ["server3"]="https://path/download/update/"
  ["server4"]="https://path/download/update/"
  ["server5"]="https://path/download/update/"
  ["server6"]="https://path/download/update/"
)

# Arrays used to store problematic elements
# useful for debugging and detailed output
declare -a OUTDATED_DEFS=()
declare -a OUTDATED_ENGINES=()

#######################################
# Usage
#######################################
# Designed to mimic standard Nagios plugins
usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]

Options:
  -w <int>    warning threshold (default: 0)
  -c <int>    critical threshold (default: 1)
  -t <int>    HTTP timeout in seconds (default: 15)
  -u <url>    override update URL (debug only)
  -b <path>   base directory for engines
  -l <path>   log directory
  -v          enable verbose mode
  -h          display help
EOF
}

#######################################
# Logging
#######################################
# Design choice:
# - stdout reserved for Centreon output
# - stderr used for debug (verbose mode)
log() {
  local msg="$*"

  if [[ "$VERBOSE" -eq 1 ]]; then
    echo "$msg" >&2
  fi

  # file logging optional (avoid mandatory dependencies)
  if [[ -n "$LOG_DIR" && -n "${LOG_FILE:-}" ]]; then
    printf '[%s] %s\n' "$(date '+%F %T')" "$msg" >> "$LOG_FILE"
  fi
}

init_log() {
  if [[ -n "$LOG_DIR" ]]; then
    mkdir -p "$LOG_DIR"
    LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}_$(date +%Y%m%d).log"
  fi
}

#######################################
# Helpers
#######################################

# Generic exit handler
# ensures consistent output + logging
die() {
  local code="$1"
  shift
  local msg="$*"
  echo "$msg"
  log "$msg"
  exit "$code"
}

# Basic validation (fail fast)
validate_number() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

validate_url() {
  [[ "$1" =~ ^https?:// ]]
}

# Cleanup old logs (avoid disk growth)
cleanup_old_logs() {
  if [[ -d "$LOG_DIR" ]]; then
    find "$LOG_DIR" -type f -name "${SCRIPT_NAME}_*" -mtime +15 -delete 2>/dev/null || true
  fi
}

#######################################
# Args parsing
#######################################
# strict validation to avoid silent misconfiguration
while getopts ":w:c:t:u:b:l:vh" opt; do
  case "$opt" in
    w) WARNING_THRESHOLD="$OPTARG" ;;
    c) CRITICAL_THRESHOLD="$OPTARG" ;;
    t) CURL_TIMEOUT="$OPTARG" ;;
    u) URL_OVERRIDE="$OPTARG" ;;
    b) BASE_AV_DIR="$OPTARG" ;;
    l) LOG_DIR="$OPTARG" ;;
    v) VERBOSE=1 ;;
    h) usage; exit 0 ;;
    *) usage; exit "$UNKNOWN" ;;
  esac
done

#######################################
# Input validation
#######################################
validate_number "$WARNING_THRESHOLD" || die "$UNKNOWN" "UNKNOWN: invalid warning threshold"
validate_number "$CRITICAL_THRESHOLD" || die "$UNKNOWN" "UNKNOWN: invalid critical threshold"
validate_number "$CURL_TIMEOUT" || die "$UNKNOWN" "UNKNOWN: invalid timeout"

# Prevent invalid threshold logic
if (( WARNING_THRESHOLD > CRITICAL_THRESHOLD )); then
  die "$UNKNOWN" "UNKNOWN: warning threshold > critical threshold"
fi

# Validate override URL if provided
if [[ -n "$URL_OVERRIDE" ]]; then
  validate_url "$URL_OVERRIDE" || die "$UNKNOWN" "UNKNOWN: invalid URL override"
fi

#######################################
# Concurrency control
#######################################
# Prevent multiple executions (important for cron / Centreon)
init_log
trap cleanup_old_logs EXIT

LOCK_FILE="/tmp/${SCRIPT_NAME}.lock"
exec 200>"$LOCK_FILE"

if ! flock -n 200; then
  die "$UNKNOWN" "UNKNOWN: another instance is already running"
fi

#######################################
# Main
#######################################
# Execution flow must be deterministic and fast
# Centreon has strict timeouts

main() {
  log "Start ${SCRIPT_NAME} on ${SRV}"

  # Step 1: resolve URL
  # (dynamic mapping or override)
  local url
  url="$(get_url)"

  # Step 2: fetch HTTP data
  # temp file used to avoid pipeline issues
  local tmp
  tmp="$(mktemp)"

  # cleanup guaranteed on exit
  trap 'rm -f "$tmp"' EXIT

  fetch_data "$url" "$tmp" || die "$CRITICAL" "CRITICAL: HTTP fetch failed"

  # Step 3: parse definitions
  local parsed
  parsed="$(parse_data "$tmp")"

  check_defs "$parsed"

  # Step 4: check engines
  check_engines

  # Step 5: compute global status
  local total
  total=$((DEF_COUNT + ENGINE_COUNT))

  build_status "$total"

  ###################################
  # Output formatting (Centreon)
  ###################################
  # stdout must follow:
  #   STATUS: message | perfdata
  # exit code defines final state

  echo "${PLUGIN_STATUS}: defs=${DEF_COUNT}, engines=${ENGINE_COUNT} | defs=${DEF_COUNT};1;2;0 engines=${ENGINE_COUNT};1;2;0"

  log "End ${SCRIPT_NAME} with status ${PLUGIN_STATUS}"

  exit "$PLUGIN_CODE"
}

main "$@"
