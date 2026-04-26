#!/usr/bin/env bash

###############################################################################
# Script: av_supervision.sh
#
# Purpose:
#   Local antivirus supervision script executed on each AV server.
#
# Role:
#   - checks antivirus definitions through HTTP content
#   - checks antivirus engines through local MANIFEST files
#   - evaluates WARNING / CRITICAL thresholds
#   - returns Centreon/Nagios-compatible output
#
# Architecture:
#   AV Server -> SSH from jump server -> SAVI aggregation -> SNMP extend -> Poller
#
# Notes:
#   - This script runs locally on the AV servers.
#   - It must return a valid Centreon plugin output:
#       STATUS: message | perfdata
#   - The exit code is the real status used by Centreon.
#
# History / Fixes:
#   - v1: initial local AV check
#   - v2: added strict bash mode
#   - v3: FIX: added lock file to avoid overlapping executions
#   - v4: FIX: added curl timeout and HTTP error handling
#   - v5: FIX: improved HTML parsing for definitions
#   - v6: FIX: definitions now use age-based logic (>24h / >48h)
#   - v7: FIX: engines MANIFEST parsing no longer assumes timestamp position
#   - v8: FIX: newest timestamp is selected when several timestamps exist
#   - v9: improved output with detailed WARNING / CRITICAL sections
#   - v10: FIX: business logic priority order corrected
#
# Business rules:
#   Definitions:
#     - age <= 24h  => OK
#     - age > 24h   => WARNING
#     - age > 48h   => CRITICAL
#
#   Engines:
#     - age <= 24h  => OK
#     - age > 24h   => WARNING
#     - age > 48h   => CRITICAL
#
#   Final status:
#     - any defs CRITICAL          => CRITICAL
#     - 4+ engines CRITICAL        => CRITICAL
#     - any defs WARNING           => WARNING
#     - any remaining engine issue => WARNING
#     - otherwise                  => OK
###############################################################################

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

###############################################################################
# Centreon / Nagios return codes
###############################################################################
OK=0
WARNING=1
CRITICAL=2
UNKNOWN=3

###############################################################################
# Defaults
###############################################################################
SCRIPT_NAME="$(basename "$0")"
SRV="$(hostname -s 2>/dev/null || hostname)"

# Shared age thresholds for definitions and engines.
WARNING_SECONDS=$((24 * 3600))
CRITICAL_SECONDS=$((48 * 3600))

# HTTP timeout.
# FIX:
#   Prevents Centreon checks from hanging indefinitely.
CURL_TIMEOUT=15

# Local AV engines base directory.
BASE_AV_DIR="/path/path/path/path/path/av"

# Local logs.
LOG_DIR="/path/path/log"
LOG_FILE=""

# Verbose mode is disabled by default to avoid polluting Centreon output.
VERBOSE=0

# Optional URL override for debug / testing.
URL_OVERRIDE=""

# HTTP paths used to retrieve definition information.
URL_PATH1="x.x-enka-antivirus/"
URL_PATH2="x.x-enka-antivirus.tar/"
WORD_KEY="enka"

# Optional integration server exception.
# Set to empty string if not used.
INTEGRATION_SERVER="server4"

###############################################################################
# Global counters
###############################################################################
DEF_COUNT=0
ENGINE_COUNT=0

DEF_WARNING_COUNT=0
DEF_CRITICAL_COUNT=0
ENGINE_WARNING_COUNT=0
ENGINE_CRITICAL_COUNT=0

declare -a OUTDATED_DEFS=()
declare -a OUTDATED_ENGINES=()

###############################################################################
# Hostname -> Update URL mapping
###############################################################################
declare -A SERVERS_URLS=(
  ["server1"]="https://path/download/update/"
  ["server2"]="https://path/download/update/"
  ["server3"]="https://path/download/update/"
  ["server4"]="https://path/download/update/"
  ["server5"]="https://path/download/update/"
  ["server6"]="https://path/download/update/"
)

###############################################################################
# Usage
###############################################################################
usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]

Options:
  -t <int>    curl timeout in seconds (default: 15)
  -u <url>    force URL override (debug/test only)
  -b <path>   AV engines base directory
  -l <path>   log directory
  -v          verbose mode
  -h          help

Examples:
  $SCRIPT_NAME
  $SCRIPT_NAME -v
  $SCRIPT_NAME -l /var/log/centreon/plugins
  $SCRIPT_NAME -u https://test.local/update/ -v
EOF
}

###############################################################################
# Logging
###############################################################################
log() {
  local msg="$*"

  # Verbose logs go to stderr only.
  # FIX:
  #   stdout must remain clean for Centreon plugin output.
  if [[ "$VERBOSE" -eq 1 ]]; then
    echo "$msg" >&2
  fi

  if [[ -n "$LOG_DIR" && -n "$LOG_FILE" ]]; then
    printf '[%s] %s\n' "$(date '+%F %T')" "$msg" >> "$LOG_FILE"
  fi
}

init_log() {
  if [[ -n "$LOG_DIR" ]]; then
    mkdir -p "$LOG_DIR"
    LOG_FILE="${LOG_DIR}/supervision_$(date +%Y%m%d).log"
  fi
}

###############################################################################
# Helpers
###############################################################################
die() {
  local code="$1"
  shift
  local msg="$*"

  echo "$msg"
  log "$msg"
  exit "$code"
}

validate_number() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+$ ]]
}

validate_url() {
  local url="$1"
  [[ "$url" =~ ^https?:// ]]
}

cleanup_old_logs() {
  # FIX:
  #   Basic log retention to avoid uncontrolled disk usage.
  if [[ -n "$LOG_DIR" && -d "$LOG_DIR" ]]; then
    find "$LOG_DIR" -type f -name "supervision_*" -mtime +15 -delete 2>/dev/null || true
  fi
}

###############################################################################
# Age classification
###############################################################################
classify_age() {
  local age_seconds="$1"

  if (( age_seconds > CRITICAL_SECONDS )); then
    echo "CRITICAL"
  elif (( age_seconds > WARNING_SECONDS )); then
    echo "WARNING"
  else
    echo "OK"
  fi
}

###############################################################################
# Arguments
###############################################################################
while getopts ":t:u:b:l:vh" opt; do
  case "$opt" in
    t) CURL_TIMEOUT="$OPTARG" ;;
    u) URL_OVERRIDE="$OPTARG" ;;
    b) BASE_AV_DIR="$OPTARG" ;;
    l) LOG_DIR="$OPTARG" ;;
    v) VERBOSE=1 ;;
    h) usage; exit 0 ;;
    \?) usage; exit "$UNKNOWN" ;;
    :) usage; exit "$UNKNOWN" ;;
  esac
done

###############################################################################
# Argument validation
###############################################################################
validate_number "$CURL_TIMEOUT" || die "$UNKNOWN" "UNKNOWN: invalid timeout"

if [[ -n "$URL_OVERRIDE" ]]; then
  validate_url "$URL_OVERRIDE" || die "$UNKNOWN" "UNKNOWN: invalid URL override"
fi

###############################################################################
# Init
###############################################################################
init_log
trap cleanup_old_logs EXIT

# FIX:
#   Prevents overlapping executions when Centreon retries while a previous run
#   is still active.
LOCK_FILE="/tmp/${SCRIPT_NAME}.lock"
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
  die "$UNKNOWN" "UNKNOWN: another instance of ${SCRIPT_NAME} is already running"
fi

###############################################################################
# Resolve target URL
###############################################################################
get_url() {
  if [[ -n "$URL_OVERRIDE" ]]; then
    echo "$URL_OVERRIDE"
    return 0
  fi

  if [[ -z "${SERVERS_URLS[$SRV]:-}" ]]; then
    die "$UNKNOWN" "UNKNOWN: no URL mapped for host ${SRV}"
  fi

  echo "${SERVERS_URLS[$SRV]}"
}

###############################################################################
# Fetch definitions data through HTTP
###############################################################################
fetch_data() {
  local url="$1"
  local tmp="$2"

  log "Fetching HTTP: ${url}${URL_PATH1}"
  curl -fsS --connect-timeout 5 --max-time "$CURL_TIMEOUT" "${url}${URL_PATH1}" > "$tmp"

  printf '\n' >> "$tmp"

  log "Fetching HTTP: ${url}${URL_PATH2}"
  curl -fsS --connect-timeout 5 --max-time "$CURL_TIMEOUT" "${url}${URL_PATH2}" >> "$tmp"
}

###############################################################################
# Parse definitions HTML/page content
###############################################################################
parse_data() {
  local file="$1"

  # FIX:
  #   Keep parsing simple and tolerant.
  #   grep may return no match, so "|| true" prevents strict mode failure.
  sed 's/<[^>]*>/ /g' "$file" \
    | grep -F "$WORD_KEY" \
    | grep -Fv "Index" \
    || true
}

###############################################################################
# Check definitions
###############################################################################
check_defs() {
  local data="$1"
  local now_ts
  now_ts="$(date +%s)"

  DEF_COUNT=0
  DEF_WARNING_COUNT=0
  DEF_CRITICAL_COUNT=0
  OUTDATED_DEFS=()

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    local name date_found date_ts age status
    name="$(awk '{print $1}' <<< "$line")"
    date_found="$(awk '{print $2}' <<< "$line")"

    if [[ -z "$name" || -z "$date_found" ]]; then
      log "DEF ignored, unreadable line: $line"
      continue
    fi

    # FIX:
    #   Invalid date is treated as CRITICAL because freshness cannot be proven.
    if ! date_ts="$(date -d "${date_found} 00:00:00" +%s 2>/dev/null)"; then
      ((DEF_CRITICAL_COUNT+=1))
      ((DEF_COUNT+=1))
      OUTDATED_DEFS+=("${name}:${date_found}:CRITICAL")
      log "DEF CRITICAL: ${name} (${date_found}) invalid date"
      continue
    fi

    age=$((now_ts - date_ts))
    status="$(classify_age "$age")"

    case "$status" in
      OK)
        log "DEF OK: ${name} (${date_found}) age=${age}s"
        ;;
      WARNING)
        ((DEF_WARNING_COUNT+=1))
        ((DEF_COUNT+=1))
        OUTDATED_DEFS+=("${name}:${date_found}:WARNING")
        log "DEF WARNING: ${name} (${date_found}) age=${age}s"
        ;;
      CRITICAL)
        ((DEF_CRITICAL_COUNT+=1))
        ((DEF_COUNT+=1))
        OUTDATED_DEFS+=("${name}:${date_found}:CRITICAL")
        log "DEF CRITICAL: ${name} (${date_found}) age=${age}s"
        ;;
    esac
  done <<< "$data"
}

###############################################################################
# Check engines
###############################################################################
check_engines() {
  ENGINE_COUNT=0
  ENGINE_WARNING_COUNT=0
  ENGINE_CRITICAL_COUNT=0
  OUTDATED_ENGINES=()

  [[ -d "$BASE_AV_DIR" ]] || die "$UNKNOWN" "UNKNOWN: missing directory: $BASE_AV_DIR"

  local now_ts
  now_ts="$(date +%s)"

  local d

  # FIX:
  #   nullglob avoids processing a literal '*' when no engine directory exists.
  shopt -s nullglob
  for d in "$BASE_AV_DIR"/*; do
    [[ -d "$d" ]] || continue

    local engine
    engine="$(basename "$d")"

    local manifest="${d}/path/MANIFEST.txt"

    if [[ ! -f "$manifest" ]]; then
      log "ENGINE ${engine}: missing manifest (${manifest})"
      OUTDATED_ENGINES+=("${engine}:manifest_absent:CRITICAL")
      ((ENGINE_CRITICAL_COUNT+=1))
      ((ENGINE_COUNT+=1))
      continue
    fi

    # FIX:
    #   Extract all timestamps and keep the newest one.
    local ts
    ts="$(
      grep -i 'timestamp' "$manifest" \
        | grep -oE '[0-9]{10,}' \
        | sort -n \
        | tail -1
    )"

    if [[ -z "$ts" ]]; then
      log "ENGINE ${engine}: no usable timestamp"
      OUTDATED_ENGINES+=("${engine}:timestamp_missing:CRITICAL")
      ((ENGINE_CRITICAL_COUNT+=1))
      ((ENGINE_COUNT+=1))
      continue
    fi

    if [[ ! "$ts" =~ ^[0-9]+$ ]]; then
      log "ENGINE ${engine}: invalid timestamp (${ts})"
      OUTDATED_ENGINES+=("${engine}:timestamp_invalid:CRITICAL")
      ((ENGINE_CRITICAL_COUNT+=1))
      ((ENGINE_COUNT+=1))
      continue
    fi

    local date_found age status
    date_found="$(date -d "@$ts" '+%Y-%m-%d %H:%M:%S')"
    age=$((now_ts - ts))
    status="$(classify_age "$age")"

    case "$status" in
      OK)
        log "ENGINE OK: ${engine} (${date_found}) age=${age}s"
        ;;
      WARNING)
        ((ENGINE_WARNING_COUNT+=1))
        ((ENGINE_COUNT+=1))
        OUTDATED_ENGINES+=("${engine}:${date_found}:WARNING")
        log "ENGINE WARNING: ${engine} (${date_found}) age=${age}s"
        ;;
      CRITICAL)
        ((ENGINE_CRITICAL_COUNT+=1))
        ((ENGINE_COUNT+=1))
        OUTDATED_ENGINES+=("${engine}:${date_found}:CRITICAL")
        log "ENGINE CRITICAL: ${engine} (${date_found}) age=${age}s"
        ;;
    esac
  done
  shopt -u nullglob
}

###############################################################################
# Build final status
###############################################################################
build_status() {

  # Integration server exception.
  # FIX:
  #   Disabled automatically if INTEGRATION_SERVER is empty.
  if [[ -n "${INTEGRATION_SERVER:-}" && "$SRV" == "$INTEGRATION_SERVER" ]]; then
    if (( DEF_WARNING_COUNT == 0 && DEF_CRITICAL_COUNT == 0 \
       && ENGINE_WARNING_COUNT == 0 && ENGINE_CRITICAL_COUNT == 0 )); then
      PLUGIN_STATUS="OK"
      PLUGIN_CODE=$OK
    else
      PLUGIN_STATUS="WARNING"
      PLUGIN_CODE=$WARNING
    fi
    return 0
  fi

  # Priority order matters.
  # FIX:
  #   Engine CRITICAL threshold must be checked before defs WARNING,
  #   otherwise a defs warning could mask a critical engine condition.
  if (( DEF_CRITICAL_COUNT > 0 )); then
    PLUGIN_STATUS="CRITICAL"
    PLUGIN_CODE=$CRITICAL
    return 0
  fi

  if (( ENGINE_CRITICAL_COUNT >= 4 )); then
    PLUGIN_STATUS="CRITICAL"
    PLUGIN_CODE=$CRITICAL
    return 0
  fi

  if (( DEF_WARNING_COUNT > 0 )); then
    PLUGIN_STATUS="WARNING"
    PLUGIN_CODE=$WARNING
    return 0
  fi

  if (( ENGINE_CRITICAL_COUNT > 0 || ENGINE_WARNING_COUNT > 0 )); then
    PLUGIN_STATUS="WARNING"
    PLUGIN_CODE=$WARNING
    return 0
  fi

  PLUGIN_STATUS="OK"
  PLUGIN_CODE=$OK
}

###############################################################################
# Main
###############################################################################
main() {
  log "Starting ${SCRIPT_NAME} on ${SRV}"

  local url
  url="$(get_url)"
  log "Selected URL: $url"

  local tmp
  tmp="$(mktemp)"

  # FIX:
  #   Always cleanup temp file on exit.
  trap 'rm -f "$tmp"; cleanup_old_logs' EXIT

  fetch_data "$url" "$tmp" || die "$CRITICAL" "CRITICAL: HTTP fetch failed"

  local parsed
  parsed="$(parse_data "$tmp")"

  check_defs "$parsed"
  check_engines

  local defs engines
  defs="${DEF_COUNT:-0}"
  engines="${ENGINE_COUNT:-0}"

  build_status

  local MSG
  MSG="${PLUGIN_STATUS}: defs=${defs}, engines=${engines}"

  local DEF_WARN_STR=""
  local DEF_CRIT_STR=""
  local ENG_WARN_STR=""
  local ENG_CRIT_STR=""

  local d
  for d in "${OUTDATED_DEFS[@]}"; do
    [[ "$d" == *":WARNING" ]] && DEF_WARN_STR+="${d}, "
    [[ "$d" == *":CRITICAL" ]] && DEF_CRIT_STR+="${d}, "
  done

  local e
  for e in "${OUTDATED_ENGINES[@]}"; do
    [[ "$e" == *":WARNING" ]] && ENG_WARN_STR+="${e}, "
    [[ "$e" == *":CRITICAL" ]] && ENG_CRIT_STR+="${e}, "
  done

  DEF_WARN_STR="${DEF_WARN_STR%, }"
  DEF_CRIT_STR="${DEF_CRIT_STR%, }"
  ENG_WARN_STR="${ENG_WARN_STR%, }"
  ENG_CRIT_STR="${ENG_CRIT_STR%, }"

  [[ -n "$DEF_WARN_STR" ]] && MSG+=" | Defs WARNING: ${DEF_WARN_STR}"
  [[ -n "$DEF_CRIT_STR" ]] && MSG+=" | Defs CRITICAL: ${DEF_CRIT_STR}"
  [[ -n "$ENG_WARN_STR" ]] && MSG+=" | Engines WARNING: ${ENG_WARN_STR}"
  [[ -n "$ENG_CRIT_STR" ]] && MSG+=" | Engines CRITICAL: ${ENG_CRIT_STR}"

  echo "$MSG | defs=${defs};1;2;0 engines=${engines};1;2;0"

  log "Finished ${SCRIPT_NAME} on ${SRV} (${PLUGIN_STATUS})"
  exit "$PLUGIN_CODE"
}

main "$@"
