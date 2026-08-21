#!/usr/bin/env bash

# Antivirus repository supervision plugin for Centreon/Nagios-compatible monitoring.
# It checks definition freshness, engine manifests, HTTP availability, and TLS certificate health.

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

OK=0
WARNING=1
CRITICAL=2
UNKNOWN=3

SCRIPT_NAME="$(basename "$0")"
SRV="$(hostname -s 2>/dev/null || hostname)"

WARNING_THRESHOLD=0
CRITICAL_THRESHOLD=1

WARNING_SECONDS=$(( 24*3600 ))
CRITICAL_SECONDS=$(( 48*3600 ))

CURL_TIMEOUT=15
BASE_AV_DIR="/path/web/to/the/update/av"
LOG_DIR="/path/to/the/antivirus/log"
LOG_FILE=""

VERBOSE=0

URL_OVERRIDE=""

TLS_WARNING_DAYS=30
TLS_WARNING_SECONDS=$((TLS_WARNING_DAYS * 24 * 3600))
TLS_CRITICAL=0

ALLOW_INSECURE_TLS="${ALLOW_INSECURE_TLS:-0}"
TLS_WARNING=0
TLS_WARNING_MSG=""
TLS_MESSAGE=""

URL_PATH1=""
URL_PATH2=""
WORD_KEY="word_keys"
INTEGRATION_SERVER="server4"

DEF_COUNT=0
ENGINE_COUNT=0

DEF_WARNING_COUNT=0
DEF_CRITICAL_COUNT=0
ENGINE_WARNING_COUNT=0
ENGINE_CRITICAL_COUNT=0

declare -A SERVERS_URLS=(
  ["server1"]="https://web/link/download/update/"
  ["server2"]="https://web/link/download/update/"
  ["server3"]="https://web/link/download/update/"
  ["server4"]="https://web/link/download/update/"

)

declare -a OUTDATED_DEFS=()
declare -a OUTDATED_ENGINES=()

# Print command-line usage.
usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]

Options:
  -w <int>    seuil warning (default: 0)
  -c <int>    critical threshold (default: 1)
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

# Write verbose diagnostics to stderr and optionally to a local log file.
log() {
  local msg="$*"
  if [[ "$VERBOSE" -eq 1 ]]; then
    echo "$msg" >&2
  fi
  if [[ -n "$LOG_DIR" && -n "$LOG_FILE" ]]; then
    printf '[%s] %s\n' "$(date '+%F %T')" "$msg" >> "$LOG_FILE"
  fi
}

# Initialize the daily log file when logging is enabled.
init_log() {
  if [[ -n "$LOG_DIR" ]]; then
    mkdir -p "$LOG_DIR"
    LOG_FILE="${LOG_DIR}/${SCRIPT_NAME%.*}_$(date +%Y%m%d).log"
  fi
}

# Emit a monitoring-compatible message and terminate with the requested status.
die() {
  local code="$1"
  shift
  local msg="$*"
  echo "$msg"
  log "$msg"
  exit "$code"
}

# Validate an unsigned integer argument.
validate_number() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+$ ]]
}

# Validate a basic HTTP/HTTPS URL.
validate_url() {
  local url="$1"
  [[ "$url" =~ ^https?:// ]]
}

# Delete old plugin logs according to the local retention policy.
cleanup_old_logs() {
  if [[ -n "$LOG_DIR" && -d "$LOG_DIR" ]]; then
    find "$LOG_DIR" -type f -name "${SCRIPT_NAME%.*}_*" -mtime +15 -delete 2>/dev/null || true
  fi
}

# Convert an object age in seconds to OK, WARNING, or CRITICAL.
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
    \?) usage; exit "$UNKNOWN" ;;
    :) usage; exit "$UNKNOWN" ;;
  esac
done

validate_number "$WARNING_THRESHOLD" || die "$UNKNOWN" "UNKNOWN: warning threshold invalide"
validate_number "$CRITICAL_THRESHOLD" || die "$UNKNOWN" "UNKNOWN: critical threshold invalide"
validate_number "$CURL_TIMEOUT" || die "$UNKNOWN" "UNKNOWN: timeout invalide"

if (( WARNING_THRESHOLD > CRITICAL_THRESHOLD )); then
  die "$UNKNOWN" "UNKNOWN: warning threshold > critical threshold"
fi

if [[ -n "$URL_OVERRIDE" ]]; then
  validate_url "$URL_OVERRIDE" || die "$UNKNOWN" "UNKNOWN: URL override invalide"
fi

init_log
trap cleanup_old_logs EXIT

LOCK_FILE="/tmp/${SCRIPT_NAME}.lock"
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
  die "$UNKNOWN" "UNKNOWN: une autre instance de ${SCRIPT_NAME} est deja en cours"
fi

# Resolve the repository URL associated with the current host.
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

# Detect the latest available antivirus repository version from a directory listing.
detect_word_keys_version() {
  local base_url="$1"
  local version=""

  version="$(
    curl -ks --connect-timeout 5 --max-time "$CURL_TIMEOUT" "$base_url" \
      | grep -oE '[0-9]+(\.[0-9]+)*-word_keys-antivirus-all/' \
      | sed 's/-word_keys-antivirus-all\/$//' \
      | sort -V \
      | tail -1 \
      || true
  )"

  echo "$version"
}

# Extract the host[:port] component from an HTTP(S) URL.
extract_host_from_url() {
  local url="$1"
  local host_port

  host_port="${url#http://}"
  host_port="${host_port#https://}"
  host_port="${host_port%%/*}"

  echo "$host_port"
}

# Validate the HTTPS certificate and raise warning/critical TLS flags.
check_tls_certificate() {
  local url="$1"
  local host_port host port cert_dates end_date

  TLS_WARNING=0
  TLS_CRITICAL=0
  TLS_MESSAGE=""

  [[ "$url" != https://* ]] && return 0

  host_port="${url#https://}"
  host_port="${host_port%%/*}"

  if [[ "$host_port" == *":"* ]]; then
    host="${host_port%%:*}"
    port="${host_port##*:}"
  else
    host="$host_port"
    port="443"
  fi

  if ! cert_dates="$(
    echo | timeout "$CURL_TIMEOUT" openssl s_client \
      -servername "$host" \
      -connect "${host}:${port}" \
      2>/dev/null \
      | openssl x509 -noout -dates 2>/dev/null
  )"; then
    TLS_CRITICAL=1
    TLS_MESSAGE="TLS certificate unreadable on ${host}:${port}"
    return 0
  fi

  if [[ -z "$cert_dates" ]]; then
    TLS_CRITICAL=1
    TLS_MESSAGE="TLS certificate unreadable on ${host}:${port}"
    return 0
  fi

  end_date="$(echo "$cert_dates" | awk -F= '/notAfter/ {print $2}')"
  if ! end_ts=$(date -d "$end_date" +%s 2>/dev/null); then
    TLS_CRITICAL=1
    TLS_MESSAGE="TLS certificate expiration date is invalid on ${host}:${port}"
    return 0
  fi
  now_ts=$(date +%s)

  days_left=$(( (end_ts - now_ts) / 86400 ))

  if ! echo | timeout "$CURL_TIMEOUT" openssl s_client \
    -servername "$host" \
    -connect "${host}:${port}" \
    2>/dev/null \
    | openssl x509 -checkend 0 -noout >/dev/null 2>&1; then
    TLS_CRITICAL=1
    TLS_MESSAGE="TLS certificate expired on ${SRV} (${host}:${port}) (${end_date})"
    return 0
  fi

  if ! echo | timeout "$CURL_TIMEOUT" openssl s_client \
    -servername "$host" \
    -connect "${host}:${port}" \
    2>/dev/null \
    | openssl x509 -checkend "$TLS_WARNING_SECONDS" -noout >/dev/null 2>&1; then
    TLS_WARNING=1
    TLS_MESSAGE="TLS certificate on ${SRV} (${host}:${port}) expires in ${days_left} day(s) (${end_date})"
    return 0
  fi
}


# Fetch the two definition repository pages used by the freshness check.
fetch_data() {
  local url="$1"
  local tmp="$2"

  local curl_err
  curl_err="$(mktemp)"

  local curl_opts
  curl_opts=(-fsS --connect-timeout 5 --max-time "$CURL_TIMEOUT")

  fetch_one() {
    local full_url="$1"
    local output_mode="$2"

    log "Fetch HTTP: ${full_url}"

    if [[ "$output_mode" == "write" ]]; then
      curl "${curl_opts[@]}" "$full_url" > "$tmp" 2>"$curl_err"
    else
      curl "${curl_opts[@]}" "$full_url" >> "$tmp" 2>"$curl_err"
    fi
  }

  fetch_one_insecure() {
    local full_url="$1"
    local output_mode="$2"

    log "Fetch HTTP insecure TLS fallback: ${full_url}"

    if [[ "$output_mode" == "write" ]]; then
      curl "${curl_opts[@]}" -k "$full_url" > "$tmp" 2>"$curl_err"
    else
      curl "${curl_opts[@]}" -k "$full_url" >> "$tmp" 2>"$curl_err"
    fi
  }

  fetch_with_tls_fallback() {
    local full_url="$1"
    local output_mode="$2"
    local err

    if fetch_one "$full_url" "$output_mode"; then
      return 0
    fi

    err="$(cat "$curl_err")"

    if [[ "$ALLOW_INSECURE_TLS" -eq 1 ]] && grep -qiE 'certificate|SSL|TLS' <<< "$err"; then
      TLS_WARNING=1
      TLS_WARNING_MSG="TLS certificate issue on ${full_url}"

      if fetch_one_insecure "$full_url" "$output_mode"; then
        return 0
      fi
    fi

    rm -f "$curl_err"
    die "$UNKNOWN" "UNKNOWN: HTTP/TLS fetch failed on ${full_url} - ${err}"
  }

  fetch_with_tls_fallback "${url}${URL_PATH1}" "write"

  printf '\n' >> "$tmp"

  fetch_with_tls_fallback "${url}${URL_PATH2}" "append"

  rm -f "$curl_err"
}

# Normalize repository HTML and retain definition-related entries.
parse_data() {
  local file="$1"
  sed 's/<[^>]*>/ /g' "$file" \
    | grep -F "$WORD_KEY" \
    | grep -Fv "Index" \
    || true
}

# Evaluate antivirus definition freshness.
check_defs() {
  local data="$1"
  local now_ts
  now_ts="$(date +%s)"

  DEF_COUNT=0
  DEF_WARNING_COUNT=0
  DEF_CRITICAL_COUNT=0
  OUTDATED_DEFS=()

  if [[ -z "${data//[[:space:]]/}" ]]; then
    DEF_CRITICAL_COUNT=1
    DEF_COUNT=1
    OUTDATED_DEFS+=("repository:no_definition_data:CRITICAL")
    log "DEF CRITICAL: no definition entries were parsed from the repository"
    return 0
  fi

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    local name date_found date_ts age status
    name="$(awk '{print $1}' <<< "$line")"
    date_found="$(awk '{print $2}' <<< "$line")"
    if [[ -z "$name" || -z "$date_found" ]]; then
      log "DEF ignoree (ligne illisible): $line"
      continue
    fi
    if ! date_ts="$(date -d "${date_found} 00:00:00" +%s 2>/dev/null)"; then
       ((DEF_CRITICAL_COUNT+=1))
       ((DEF_COUNT+=1))
       OUTDATED_DEFS+=("${name}:${date_found}:CRITICAL")
       log "DEF CRITICAL: ${name} (${date_found}) date invalide"
       continue
    fi

    age=$((now_ts - date_ts))
    if (( age < 0 )); then
      status="CRITICAL"
    else
      status="$(classify_age "$age")"
    fi

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

# Evaluate local antivirus engine manifests and timestamps.
check_engines() {
  ENGINE_COUNT=0
  ENGINE_WARNING_COUNT=0
  ENGINE_CRITICAL_COUNT=0
  OUTDATED_ENGINES=()

  [[ -d "$BASE_AV_DIR" ]] || die "$UNKNOWN" "UNKNOWN: repertoire absent: $BASE_AV_DIR"

  local now_ts
  now_ts="$(date +%s)"

  local d
  local engine_dir_count=0
  shopt -s nullglob
  for d in "$BASE_AV_DIR"/*; do
    ((engine_dir_count+=1))
    [[ -d "$d" ]] || continue

    local engine
    engine="$(basename "$d")"

    local manifest="${d}/path/to/the/file/MANIFEST.txt"
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
        | tail -1 \
        || true
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
    date_found="$(date -d "@$ts" '+%Y%m%d')"
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

  if (( engine_dir_count == 0 )); then
    ENGINE_CRITICAL_COUNT=1
    ENGINE_COUNT=1
    OUTDATED_ENGINES+=("repository:no_engine_directory:CRITICAL")
    log "ENGINE CRITICAL: no engine directory found under ${BASE_AV_DIR}"
  fi
}

# Build the final Centreon/Nagios status from collected severities.
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
  if (( DEF_CRITICAL_COUNT > 0 )); then
     PLUGIN_STATUS="CRITICAL"
     PLUGIN_CODE=$CRITICAL
     return 0
  fi

  if (( TLS_CRITICAL == 1 )); then
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

  if (( TLS_WARNING == 1 )); then
    PLUGIN_STATUS="WARNING"
    PLUGIN_CODE=$WARNING
    return 0
  fi

  if (( ENGINE_CRITICAL_COUNT > 0 || ENGINE_WARNING_COUNT > 0 )); then
    PLUGIN_STATUS="WARNING"
    PLUGIN_CODE=$WARNING
    return 0
  fi

  if (( TLS_WARNING == 1 )); then
    PLUGIN_STATUS="WARNING"
    PLUGIN_CODE=$WARNING
    return 0
  fi

    PLUGIN_STATUS="OK"
    PLUGIN_CODE=$OK
}

# Main program entrypoint.
main() {
  log "Debut ${SCRIPT_NAME} sur ${SRV}"

  local url
  url="$(get_url)"
  log "URL retenue: $url"

  local word_keys_version
  word_keys_version="$(detect_word_keys_version "$url")"
  if [[ -z "$word_keys_version" ]]; then
    die "$CRITICAL" "CRITICAL: unable to detect word_keys version from ${url}"
  fi
  URL_PATH1="${word_keys_version}-word_keys-antivirus-all/"
  URL_PATH2="${word_keys_version}-word_keys-antivirus.tar/"

  log "Detect word_keys version: ${word_keys_version}"
  log "Using URL_PATH1: ${URL_PATH1}"
  log "Using URL_PATH2: ${URL_PATH2}"

  check_tls_certificate "$url"

  local tmp
  tmp="$(mktemp)"
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

  local total=0
  total=$((defs + engines))

  build_status "$total"

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

  if (( TLS_WARNING == 1 )); then
    MSG+=" | TLS WARNING: ${TLS_MESSAGE}"
  fi

  if (( TLS_CRITICAL == 1 )); then
    MSG+=" | TLS CRITICAL: ${TLS_MESSAGE}"
  fi

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

  log "Fin ${SCRIPT_NAME} sur ${SRV} (${PLUGIN_STATUS})"
  exit "$PLUGIN_CODE"
}

main "$@"
