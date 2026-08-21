#!/usr/bin/env bash

# Aggregation plugin that executes the remote antivirus check on multiple servers in parallel.
# The first server is used as the functional reference; differences and technical errors are consolidated.

set -uo pipefail

OK=0
WARNING=1
CRITICAL=2
UNKNOWN=3

REMOTE_SCRIPT="/path/to/the/script_sup.sh"
SSH_TIMEOUT=15
SSH_STRICT_HOST_KEY_CHECKING="${SSH_STRICT_HOST_KEY_CHECKING:-accept-new}"

SERVERS=(
  "server1"
  "server2"
  "server3"
)

# Translate technical return codes into short human-readable labels.
translate_rc() {
  local rc="${1:-}"

  case "$rc" in
    124) echo "timeout" ;;
    127) echo "command not found" ;;
    255) echo "ssh error" ;;
    1)   echo "generic error" ;;
    2)   echo "critical error" ;;
    3)   echo "unknown error" ;;
    "")  echo "unknown rc" ;;
    *)   echo "rc=${rc}" ;;
  esac
}

# Execute the remote plugin over SSH and preserve both output and return code.
run_remote_check() {
  local server="${1:-}"
  local output=""
  local rc=0

  if [[ -z "$server" ]]; then
    echo "UNKNOWN: empty server name"
    return "$UNKNOWN"
  fi

  output="$(
    ssh -o BatchMode=yes \
        -o ConnectTimeout="${SSH_TIMEOUT}" \
        -o StrictHostKeyChecking="${SSH_STRICT_HOST_KEY_CHECKING}" \
        "$server" "$REMOTE_SCRIPT" 2>&1
  )"
  rc=$?

  printf '%s\n' "${output:-}"
  return "$rc"
}

# Extract a numeric metric from Nagios/Centreon performance data.
extract_metric() {
  local result="${1:-}"
  local metric="${2:-}"
  local perfdata=""

  [[ -z "$result" || -z "$metric" ]] && return 0

  perfdata="${result#*|}"

  awk -v metric="$metric" '
    {
      for (i = 1; i <= NF; i++) {
        if ($i ~ "^" metric "=") {
          split($i, a, "=")
          split(a[2], b, ";")
          print b[1]
          exit
        }
      }
    }
  ' <<< "$perfdata"
}

# Remove performance data and normalize plugin output for Centreon display.
clean_status_text() {
  local result="${1:-}"
  local text=""

  text="$result"

  text="$(sed -E 's/[[:space:]]+\|[[:space:]]+[A-Za-z0-9_]+=.+$//' <<< "$text")"

  text="${text//|/ - }"

  text="${text%"${text##*[![:space:]]}"}"
  text="${text#"${text%%[![:space:]]*}"}"

  printf '%s\n' "${text:-}"
}

# Extract the human-readable detail section from plugin output.
extract_detail_text() {
  local result="${1:-}"
  local detail=""

  [[ "$result" != *"|"* ]] && return 0

  detail="${result#*|}"
  detail="$(sed -E 's/[[:space:]]+\|[[:space:]]+[A-Za-z0-9_]+=.+$//' <<< "$detail")"

  detail="${detail//|/ - }"

  detail="${detail%"${detail##*[![:space:]]}"}"
  detail="${detail#"${detail%%[![:space:]]*}"}"

  printf '%s\n' "${detail:-}"
}

# Limit long remote messages to avoid oversized monitoring output.
truncate_text() {
  local text="${1:-}"
  local max_len="${2:-3000}"

  if (( ${#text} > max_len )); then
    printf '%s...\n' "${text:0:max_len}"
  else
    printf '%s\n' "$text"
  fi
}

declare -A SERVER_RC=()
declare -A SERVER_DEFS=()
declare -A SERVER_ENGINES=()
declare -A SERVER_RAW=()

declare -A DIFF_GROUPS=()

# Main program entrypoint.
main() {
  local tmpdir=""
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/antivirus_wrapper.XXXXX")"
  trap 'rm -rf "$tmpdir"' EXIT

  local server=""
  local -a technical_errors=()
  local -a diff_msgs=()
  local -A COUNTED_SERVERS=()
  local -A CONTEXT_GROUPS=()
  local -a context_results=()

  local ref_server=""
  local ref_defs="0"
  local ref_engines="0"
  local ref_rc="$UNKNOWN"

  local has_critical=0
  local has_warning=0
  local has_hard_technical_error=0
  local antivirus=0

  local current_defs=""
  local current_engines=""
  local current_rc=0
  local raw_text=""
  local diff_str=""
  local context_str=""
  local ref_detail=""
  local defs_out="0"
  local engines_out="0"
  local msg=""

  for server in "${SERVERS[@]}"; do
    {
      result="$(run_remote_check "$server")"
      rc=$?

      printf '%s\n' "${result:-}" > "${tmpdir}/${server}.out"
      printf '%s\n' "${rc:-}" > "${tmpdir}/${server}.rc"
    } &
  done
  wait

  for server in "${SERVERS[@]}"; do

    result="$(cat "${tmpdir}/${server}.out" 2>/dev/null || true)"
    rc="$(cat "${tmpdir}/${server}.rc" 2>/dev/null || echo 3)"

    SERVER_RAW["$server"]="${result:-}"
    SERVER_RC["$server"]="${rc:-3}"

    if (( rc < 0 || rc > 2 )); then
      rc_msg="$(translate_rc "$rc")"
      raw_msg="$(clean_status_text "$result")"
      raw_msg="$(truncate_text "$raw_msg")"

      technical_errors+=("${server}: ${rc_msg} (rc=${rc}) -> ${raw_msg}")
      continue
    fi

    defs="$(extract_metric "$result" "defs")"
    engines="$(extract_metric "$result" "engines")"

    if [[ -z "$defs" || -z "$engines" ]]; then
      SERVER_RC["$server"]="$UNKNOWN"
      raw_msg="$(clean_status_text "$result")"
      raw_msg="$(truncate_text "$raw_msg" 3000)"
      technical_errors+=("${server}: invalid plugin perfdata (rc=${UNKNOWN}) -> ${raw_msg:-empty output}")
      continue
    fi

    SERVER_DEFS["$server"]="$defs"
    SERVER_ENGINES["$server"]="$engines"
  done

  ref_server="${SERVERS[0]}"
  ref_defs="${SERVER_DEFS[$ref_server]:-0}"
  ref_engines="${SERVER_ENGINES[$ref_server]:-0}"
  ref_rc="${SERVER_RC[$ref_server]:-$UNKNOWN}"

  if (( ref_rc == CRITICAL )); then
    has_critical=1
  elif (( ref_rc == WARNING )); then
    has_warning=1
  fi

  for server in "${SERVERS[@]:1}"; do
    [[ -z "${SERVER_DEFS[$server]:-}" || -z "${SERVER_ENGINES[$server]:-}" ]] && continue

    current_defs="${SERVER_DEFS[$server]}"
    current_engines="${SERVER_ENGINES[$server]}"
    current_rc="${SERVER_RC[$server]:-$UNKNOWN}"

    if (( current_rc == CRITICAL )); then
      has_critical=1
    elif (( current_rc == WARNING )); then
      has_warning=1
    fi

    if [[ "$current_defs" != "$ref_defs" || "$current_engines" != "$ref_engines" ]]; then
      if [[ -z "${COUNTED_SERVERS[$server]:-}" ]]; then
        ((antivirus+=1))
        COUNTED_SERVERS["$server"]=1
      fi

      raw_text="$(clean_status_text "${SERVER_RAW[$server]:-}")"
      raw_text="$(truncate_text "$raw_text" 3000)"

      if [[ -n "${DIFF_GROUPS[$raw_text]:-}" ]]; then
        DIFF_GROUPS["$raw_text"]+=",${server}"
      else
        DIFF_GROUPS["$raw_text"]="$server"
      fi
    fi
  done

  for server in "${SERVERS[@]}"; do
    [[ -z "${SERVER_RAW[$server]:-}" ]] && continue

    raw_text="$(clean_status_text "${SERVER_RAW[$server]:-}")"
    raw_text="$(truncate_text "$raw_text" 3000)"

    if [[ "$raw_text" == *"TLS WARNING"* || "$raw_text" == *"certificate"* || "$raw_text" == *"certificat"* ]]; then
      if [[ -z "${COUNTED_SERVERS[$server]:-}" ]]; then
        ((antivirus+=1))
        COUNTED_SERVERS["$server"]=1
      fi

      if [[ -n "${DIFF_GROUPS[$raw_text]:-}" ]]; then
        DIFF_GROUPS["$raw_text"]+=",${server}"
      else
        DIFF_GROUPS["$raw_text"]="$server"
      fi

      has_warning=1
    fi
  done

  if (( ${#technical_errors[@]} > 0 )); then
    local err=""
    for err in "${technical_errors[@]}"; do
      ((antivirus+=1))
      diff_msgs+=("$err")

      if [[ "$err" == *"rc=255"* || "$err" == *"rc=127"* || "$err" == *"rc=124"* ]]; then
        has_hard_technical_error=1
      else
        has_warning=1
      fi
    done
  fi

  if (( ${#DIFF_GROUPS[@]} > 0 )); then
    local grouped_diff=""
    for grouped_diff in "${!DIFF_GROUPS[@]}"; do
      diff_msgs+=("[${DIFF_GROUPS[$grouped_diff]}] ${grouped_diff}")
    done
  fi

  if (( ${#diff_msgs[@]} > 0 )); then
    printf -v diff_str "%s ; " "${diff_msgs[@]}"
    diff_str="${diff_str% ; }"
  fi

  for server in "${SERVERS[@]}"; do
    [[ -n "${COUNTED_SERVERS[$server]:-}" ]] && continue
    [[ -z "${SERVER_RAW[$server]:-}" ]] && continue

    raw_text="$(clean_status_text "${SERVER_RAW[$server]:-}")"
    raw_text="$(truncate_text "$raw_text" 3000)"

    if [[ -n "${CONTEXT_GROUPS[$raw_text]:-}" ]]; then
      CONTEXT_GROUPS["$raw_text"]+=",${server}"
    else
      CONTEXT_GROUPS["$raw_text"]="$server"
    fi
  done

  if (( ${#CONTEXT_GROUPS[@]} > 0 )); then
    local grouped_context=""
    for grouped_context in "${!CONTEXT_GROUPS[@]}"; do
      context_results+=("[${CONTEXT_GROUPS[$grouped_context]}] ${grouped_context}")
    done

    printf -v context_str "%s ; " "${context_results[@]}"
    context_str="${context_str% ; }"
  fi

  if [[ -n "${SERVER_RAW[$ref_server]:-}" ]]; then
    ref_detail="$(extract_detail_text "${SERVER_RAW[$ref_server]:-}")"
    ref_detail="$(truncate_text "$ref_detail" 3000)"
  fi

  defs_out="$ref_defs"
  engines_out="$ref_engines"

  if (( has_hard_technical_error == 1 )); then
    msg="CRITICAL: antivirus=${antivirus}"
    [[ -n "$context_str" ]] && msg+=" - results: ${context_str}"
    [[ -n "$diff_str" ]] && msg+=" - diff: ${diff_str}"
    echo "${msg}"
    exit "$CRITICAL"
  fi

  if (( has_critical == 1 )); then
    if (( antivirus >= 1 )); then
      msg="CRITICAL: antivirus=${antivirus}"
      [[ -n "$context_str" ]] && msg+=" - results: ${context_str}"
      [[ -n "$diff_str" ]] && msg+=" - diff: ${diff_str}"
    else
      msg="CRITICAL: antivirus=${antivirus}, defs=${defs_out}, engines=${engines_out}"
      [[ -n "$context_str" ]] && msg+=" - results: ${context_str}"
      [[ -z "$context_str" && -n "$ref_detail" ]] && msg+=" - ${ref_detail}"
    fi

    echo "${msg}"
    exit "$CRITICAL"
  fi

  if (( antivirus >= 1 )); then
    msg="WARNING: antivirus=${antivirus}"
    [[ -n "$context_str" ]] && msg+=" - results: ${context_str}"
    [[ -n "$diff_str" ]] && msg+=" - diff: ${diff_str}"
    echo "${msg}"
    exit "$WARNING"
  fi

  if (( has_warning == 1 )); then
    msg="WARNING: antivirus=${antivirus}, defs=${defs_out}, engines=${engines_out}"
    [[ -n "$context_str" ]] && msg+=" - results: ${context_str}"
    [[ -z "$context_str" && -n "$ref_detail" ]] && msg+=" - ${ref_detail}"
    echo "${msg}"
    exit "$WARNING"
  fi

  msg="OK: antivirus=${antivirus}, defs=${defs_out}, engines=${engines_out}"
  echo "${msg}"
  exit "$OK"
}

main "$@"
