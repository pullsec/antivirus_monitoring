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
#   AV Server -> SSH (jump) -> SNMP -> Poller -> Centreon
#
# Notes:
#   - Designed for segmented environments (no direct access)
#   - Output must follow Nagios/Centreon plugin format
#   - Exit code is critical (message is secondary)
#
# Environment:
#   Debian / Ubuntu
#
# Rework / fixes done:
#   - proper bash strict mode
#   - lock to avoid concurrent execution
#   - better debug / verbose logging
#   - MANIFEST parsing fix:
#       timestamp not assumed to be on first line anymore
#   - aligned logic for defs and engines:
#       > 24h => WARNING
#       > 48h => CRITICAL
#   - enriched Centreon output with explicit WARNING / CRITICAL details
#
# Known limitation:
#   - defs source seems to expose only a date (YYYY-MM-DD) and not a full time
#   - so for defs we evaluate age from 00:00:00 of that day
######################################

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

#######################################
# Codes Centreon / Nagios
#######################################
OK=0
WARNING=1
CRITICAL=2
UNKNOWN=3

#######################################
# Defaults
#######################################

# Init
SCRIPT_NAME="$(basename "$0")"
SRV="$(hostname -s 2>/dev/null || hostname)"

# Common freshness thresholds
WARNING_SECONDS=$((24 * 3600))
CRITICAL_SECONDS=$((48 * 3600))

CURL_TIMEOUT=15
BASE_AV_DIR="/path/path/path/path/path/av"
LOG_DIR="/path/path/log"
LOG_FILE=""

# Debug
VERBOSE=0

# URL test/debug
URL_OVERRIDE=""

URL_PATH1="x.x-enka-antivirus/"
URL_PATH2="x.x-enka-antivirus.tar/"
WORD_KEY="enka"
INTEGRATION_SERVER="server4"

# Global counters kept for display/debug
DEF_COUNT=0
ENGINE_COUNT=0

# Severity counters
DEF_WARNING_COUNT=0
DEF_CRITICAL_COUNT=0
ENGINE_WARNING_COUNT=0
ENGINE_CRITICAL_COUNT=0

#######################################
# Mapping
#######################################
declare -A SERVERS_URLS=(
  ["server1"]="https://path/download/update/"
  ["server2"]="https://path/download/update/"
  ["server3"]="https://path/download/update/"
  ["server4"]="https://path/download/update/"
  ["server5"]="https://path/download/update/"
  ["server6"]="https://path/download/update/"
)

# Detail arrays.
# Format kept intentionally human-readable:
#   name:date:WARNING
#   name:date:CRITICAL
declare -a OUTDATED_DEFS=()
declare -a OUTDATED_ENGINES=()

#######################################
# Usage
#######################################
usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]

Options:
  -t <int>    timeout curl en secondes (default: 15)
  -u <url>    URL force (debug/test uniquement)
  -b <path>   repertoire base des engines
  -l <path>   repertoire de logs
  -v          mode verbose
  -h          aide

Exemples:
  $SCRIPT_NAME
  $SCRIPT_NAME -v
  $SCRIPT_NAME -l /var/log/centreon/plugins
  $SCRIPT_NAME -u https://test.local/update/ -v
EOF
}

#######################################
# Logging
#######################################

# verbose on stderr to avoid polluting plugin stdout
log() {
  local msg="$*"

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

#######################################
# Helper functions
#######################################
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
  if [[ -n "$LOG_DIR" && -d "$LOG_DIR" ]]; then
    find "$LOG_DIR" -type f -name "supervision_*" -mtime +15 -delete 2>/dev/null || true
  fi
}

#######################################
# Age classification
#######################################
# Shared logic for defs and engines:
#   <= 24h => OK
#   > 24h  => WARNING
#   > 48h  => CRITICAL
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

#######################################
# Args
#######################################
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

#######################################
# Argument checks
#######################################
validate_number "$CURL_TIMEOUT" || die "$UNKNOWN" "UNKNOWN: timeout invalide"

if [[ -n "$URL_OVERRIDE" ]]; then
  validate_url "$URL_OVERRIDE" || die "$UNKNOWN" "UNKNOWN: URL override invalide"
fi

#######################################
# Init logs
#######################################
init_log
trap cleanup_old_logs EXIT

# Fix:
# avoid a second execution interfering with the first one
LOCK_FILE="/tmp/${SCRIPT_NAME}.lock"
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
  die "$UNKNOWN" "UNKNOWN: une autre instance de ${SCRIPT_NAME} est deja en cours"
fi

#######################################
# URL cible
#######################################
get_url() {
  if [[ -n "$URL_OVERRIDE" ]]; then
    echo "$URL_OVERRIDE"
    return 0
  fi

  if [[ -z "${SERVERS_URLS[$SRV]:-}" ]]; then
    die "$UNKNOWN" "UNKNOWN: aucune URL associee a l'hote $SRV"
  fi

  echo "${SERVERS_URLS[$SRV]}"
}

#######################################
# HTTP defs retrieval
#######################################
# Notes:
#   - curl timeout kept explicit
#   - fail on HTTP error
#   - both sources are concatenated in a temp file
fetch_data() {
  local url="$1"
  local tmp="$2"

  log "Fetch HTTP: ${url}${URL_PATH1}"
  curl -fsS --connect-timeout 5 --max-time "$CURL_TIMEOUT" "${url}${URL_PATH1}" > "$tmp"

  printf '\n' >> "$tmp"

  log "Fetch HTTP: ${url}${URL_PATH2}"
  curl -fsS --connect-timeout 5 --max-time "$CURL_TIMEOUT" "${url}${URL_PATH2}" >> "$tmp"
}

#######################################
# Defs parsing
#######################################
# Still depends on the actual HTML / directory listing format.
# Kept simple on purpose for now.
parse_data() {
  local file="$1"

  sed 's/<[^>]*>/ /g' "$file" \
    | grep -F "$WORD_KEY" \
    | grep -Fv "Index" \
    || true
}

#######################################
# Check defs
#######################################
# Current business logic:
#   - defs freshness based on age
#   - source only gives YYYY-MM-DD
#   - age therefore computed from YYYY-MM-DD 00:00:00
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
      log "DEF ignoree (ligne illisible): $line"
      continue
    fi

    # If the source date cannot be parsed, keep it critical.
    if ! date_ts="$(date -d "${date_found} 00:00:00" +%s 2>/dev/null)"; then
      ((DEF_CRITICAL_COUNT+=1))
      ((DEF_COUNT+=1))
      OUTDATED_DEFS+=("${name}:${date_found}:CRITICAL")
      log "DEF CRITICAL: ${name} (${date_found}) date invalide"
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

#######################################
# Check engines
#######################################
# Notes:
#   - MANIFEST timestamp is not assumed to be on first line anymore
#   - we extract all timestamps and keep the newest one
check_engines() {
  ENGINE_COUNT=0
  ENGINE_WARNING_COUNT=0
  ENGINE_CRITICAL_COUNT=0
  OUTDATED_ENGINES=()

  [[ -d "$BASE_AV_DIR" ]] || die "$UNKNOWN" "UNKNOWN: repertoire absent: $BASE_AV_DIR"

  local now_ts
  now_ts="$(date +%s)"

  local d
  # nullglob avoids treating unmatched globs as raw strings
  shopt -s nullglob
  for d in "$BASE_AV_DIR"/*; do
    [[ -d "$d" ]] || continue

    local engine
    engine="$(basename "$d")"

    # Adjust this path if needed in your environment
    local manifest="${d}/path/MANIFEST.txt"

    if [[ ! -f "$manifest" ]]; then
      log "ENGINE ${engine}: manifest absent (${manifest})"
      OUTDATED_ENGINES+=("${engine}:manifest_absent:CRITICAL")
      ((ENGINE_CRITICAL_COUNT+=1))
      ((ENGINE_COUNT+=1))
      continue
    fi

    local ts
    ts="$(
      grep -i 'timestamp' "$manifest" \
        | grep -oE '[0-9]{10,}' \
        | sort -n \
        | tail -1
    )"

    if [[ -z "$ts" ]]; then
      log "ENGINE ${engine}: aucun timestamp exploitable"
      OUTDATED_ENGINES+=("${engine}:timestamp_introuvable:CRITICAL")
      ((ENGINE_CRITICAL_COUNT+=1))
      ((ENGINE_COUNT+=1))
      continue
    fi

    if [[ ! "$ts" =~ ^[0-9]+$ ]]; then
      log "ENGINE ${engine}: timestamp invalide (${ts})"
      OUTDATED_ENGINES+=("${engine}:timestamp_invalide:CRITICAL")
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

#######################################
# Build status
#######################################
# Final status is severity-based now:
#   - at least one CRITICAL => CRITICAL
#   - else at least one WARNING => WARNING
#   - else OK
#
# Integration server kept softer on purpose.
build_status() {
  if [[ "$SRV" == "$INTEGRATION_SERVER" ]]; then
    if (( DEF_WARNING_COUNT == 0 && DEF_CRITICAL_COUNT == 0 && ENGINE_WARNING_COUNT == 0 && ENGINE_CRITICAL_COUNT == 0 )); then
      PLUGIN_STATUS="OK"
      PLUGIN_CODE=$OK
    else
      PLUGIN_STATUS="WARNING"
      PLUGIN_CODE=$WARNING
    fi
    return 0
  fi

  if (( DEF_CRITICAL_COUNT > 0 || ENGINE_CRITICAL_COUNT > 0 )); then
    PLUGIN_STATUS="CRITICAL"
    PLUGIN_CODE=$CRITICAL
    return 0
  fi

  if (( DEF_WARNING_COUNT > 0 || ENGINE_WARNING_COUNT > 0 )); then
    PLUGIN_STATUS="WARNING"
    PLUGIN_CODE=$WARNING
    return 0
  fi

  PLUGIN_STATUS="OK"
  PLUGIN_CODE=$OK
}

#######################################
# Main
#######################################
main() {
  log "Debut ${SCRIPT_NAME} sur ${SRV}"

  local url
  url="$(get_url)"
  log "URL retenue: $url"

  local tmp
  tmp="$(mktemp)"
  # temp file is cleaned on exit
  trap 'rm -f "$tmp"; cleanup_old_logs' EXIT

  fetch_data "$url" "$tmp" || die "$CRITICAL" "CRITICAL: echec recuperation HTTP"

  local parsed
  parsed="$(parse_data "$tmp")"

  check_defs "$parsed"
  check_engines

  local defs=0
  local engines=0
  defs="${DEF_COUNT:-0}"
  engines="${ENGINE_COUNT:-0}"

  build_status

  # Human-readable Centreon message
  local MSG
  MSG="${PLUGIN_STATUS}: defs=${defs}, engines=${engines}"

  local DEF_WARN_STR=""
  local DEF_CRIT_STR=""
  local ENG_WARN_STR=""
  local ENG_CRIT_STR=""

  local d
  for d in "${OUTDATED_DEFS[@]}"; do
    if [[ "$d" == *":WARNING" ]]; then
      DEF_WARN_STR+="${d}, "
    elif [[ "$d" == *":CRITICAL" ]]; then
      DEF_CRIT_STR+="${d}, "
    fi
  done

  local e
  for e in "${OUTDATED_ENGINES[@]}"; do
    if [[ "$e" == *":WARNING" ]]; then
      ENG_WARN_STR+="${e}, "
    elif [[ "$e" == *":CRITICAL" ]]; then
      ENG_CRIT_STR+="${e}, "
    fi
  done

  DEF_WARN_STR="${DEF_WARN_STR%, }"
  DEF_CRIT_STR="${DEF_CRIT_STR%, }"
  ENG_WARN_STR="${ENG_WARN_STR%, }"
  ENG_CRIT_STR="${ENG_CRIT_STR%, }"

  [[ -n "$DEF_WARN_STR" ]] && MSG+=" | Defs WARNING: ${DEF_WARN_STR}"
  [[ -n "$DEF_CRIT_STR" ]] && MSG+=" | Defs CRITICAL: ${DEF_CRIT_STR}"
  [[ -n "$ENG_WARN_STR" ]] && MSG+=" | Engines WARNING: ${ENG_WARN_STR}"
  [[ -n "$ENG_CRIT_STR" ]] && MSG+=" | Engines CRITICAL: ${ENG_CRIT_STR}"

  # Perfdata kept for Centreon graph / history
  echo "$MSG | defs=${defs};1;2;0 engines=${engines};1;2;0"

  if [[ "$VERBOSE" -eq 1 ]]; then
    if (( ${#OUTDATED_DEFS[@]} > 0 )); then
      echo "Defs en cause :" >&2
      printf '  - %s\n' "${OUTDATED_DEFS[@]}" >&2
    fi

    if (( ${#OUTDATED_ENGINES[@]} > 0 )); then
      echo "Engines en cause :" >&2
      printf '  - %s\n' "${OUTDATED_ENGINES[@]}" >&2
    fi
  fi

  # Exit code is what Centreon really uses for status
  log "Fin ${SCRIPT_NAME} sur ${SRV} (${PLUGIN_STATUS})"
  exit "$PLUGIN_CODE"
}

main "$@"
