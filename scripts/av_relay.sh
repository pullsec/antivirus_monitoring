#!/usr/bin/env bash

###############################################################################
# Script: av_relay.sh
#
# Author: root (iteratively improved / debugged / stabilized)
#
# Purpose:
#   Compare antivirus status across multiple servers and detect inconsistencies.
#
# Core logic:
#   - srv1 is used as the reference
#   - srv2 / srv3 are compared against srv1
#   - srv = number of servers that are:
#       * different from the reference
#       * OR not technically reachable / exploitable
#
# Global status rules:
#   - CRITICAL if data collection is incomplete
#   - CRITICAL if at least one server is CRITICAL
#   - WARNING if srv >= 1 (inconsistency or failure)
#   - WARNING if all servers are consistent but at least one is WARNING
#   - OK otherwise
#
# History / Fixes:
#   - v1: basic multi-server comparison
#   - v2: added srv logic (consistency indicator)
#   - v3: improved parsing of perfdata (defs / engines)
#   - v4: FIX: handle SSH / timeout / unreachable servers
#   - v5: FIX: avoid false positives when parsing fails
#   - v6: improvement: clearer output (results vs diff)
#   - v7: FIX: srv now includes technical failures (not only diffs)
#
# Notes:
#   - Designed for segmented environments (SSH via jump server)
#   - Output must comply with Centreon/Nagios plugin format
#   - Exit code drives status, message is informational
###############################################################################

set -uo pipefail

OK=0
WARNING=1
CRITICAL=2
UNKNOWN=3

# Remote script executed on each AV server
REMOTE_SCRIPT="/usr/local/bin/av_supervision.sh"

# SSH timeout to avoid long blocking checks
# FIX: prevents poller timeout / UNKNOWN states
SSH_TIMEOUT=8

# First server = reference
SERVERS=(
  "srv1"
  "srv2"
  "srv3"
)

###############################################################################
# Translate technical return codes into human-readable messages
#
# FIX:
#   Improves troubleshooting without needing SSH access
###############################################################################
translate_rc() {
  local rc="$1"

  case "$rc" in
    124) echo "timeout" ;;
    127) echo "command not found" ;;
    255) echo "ssh error" ;;
    1)   echo "generic error" ;;
    2)   echo "critical error" ;;
    3)   echo "unknown error" ;;
    *)   echo "rc=${rc}" ;;
  esac
}

###############################################################################
# Execute remote check via SSH
#
# FIX:
#   - BatchMode avoids password prompts
#   - ConnectTimeout prevents long hangs
###############################################################################
run_remote_check() {
  local server="$1"
  local output rc

  output="$(
    ssh -o BatchMode=yes \
        -o ConnectTimeout="${SSH_TIMEOUT}" \
        -o StrictHostKeyChecking=no \
        "$server" "$REMOTE_SCRIPT" 2>&1
  )"
  rc=$?

  printf '%s\n' "$output"
  return "$rc"
}

###############################################################################
# Extract metric from perfdata
#
# FIX:
#   Robust parsing even if ordering changes
###############################################################################
extract_metric() {
  local result="$1"
  local metric="$2"

  local perfdata
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

###############################################################################
# Clean human-readable message (remove perfdata)
#
# FIX:
#   Keep useful info (WARNING / CRITICAL details)
#   Remove only performance data
###############################################################################
clean_status_text() {
  local result="$1"
  local text

  text="$result"
  text="$(sed -E 's/[[:space:]]+\|[[:space:]]+[A-Za-z0-9_]+=.+$//' <<< "$text")"

  # trim spaces
  text="${text%"${text##*[![:space:]]}"}"
  text="${text#"${text%%[![:space:]]*}"}"

  printf '%s\n' "$text"
}

###############################################################################
# Extract only detailed part (after first "|")
###############################################################################
extract_detail_text() {
  local result="$1"
  local detail

  [[ "$result" != *"|"* ]] && return 0

  detail="${result#*|}"
  detail="$(sed -E 's/[[:space:]]+\|[[:space:]]+[A-Za-z0-9_]+=.+$//' <<< "$detail")"

  detail="${detail%"${detail##*[![:space:]]}"}"
  detail="${detail#"${detail%%[![:space:]]*}"}"

  printf '%s\n' "$detail"
}

###############################################################################
# Truncate long output
#
# FIX:
#   Prevent Centreon UI overflow
###############################################################################
truncate_text() {
  local text="$1"
  local max_len="${2:-1000}"

  if (( ${#text} > max_len )); then
    printf '%s...\n' "${text:0:max_len}"
  else
    printf '%s\n' "$text"
  fi
}

###############################################################################
# Result storage
###############################################################################
declare -A SERVER_RC=()
declare -A SERVER_DEFS=()
declare -A SERVER_ENGINES=()
declare -A SERVER_RAW=()

###############################################################################
# Collect data from one server
#
# FIX:
#   - separate collection from analysis
#   - handle parsing failures explicitly
###############################################################################
collect_server_data() {
  local server="$1"

  local result rc defs engines

  set +e
  result="$(run_remote_check "$server")"
  rc=$?
  set -e

  SERVER_RAW["$server"]="$result"
  SERVER_RC["$server"]="$rc"

  # Only 0/1/2 are considered usable results
  if (( rc < 0 || rc > 2 )); then
    return 1
  fi

  defs="$(extract_metric "$result" "defs")"
  engines="$(extract_metric "$result" "engines")"

  # FIX: invalid parsing => treat as UNKNOWN
  if [[ -z "$defs" || -z "$engines" ]]; then
    SERVER_RC["$server"]="$UNKNOWN"
    return 1
  fi

  SERVER_DEFS["$server"]="$defs"
  SERVER_ENGINES["$server"]="$engines"

  return 0
}

###############################################################################
# Main
###############################################################################
main() {
  local server
  local technical_errors=()
  local ok_results=()

  ###########################################################################
  # 1. Collect data
  ###########################################################################
  for server in "${SERVERS[@]}"; do
    if ! collect_server_data "$server"; then
      rc_msg="$(translate_rc "${SERVER_RC[$server]}")"
      technical_errors+=("${server}: ${rc_msg} (rc=${SERVER_RC[$server]})")
    else
      clean="$(clean_status_text "${SERVER_RAW[$server]}")"
      clean="$(truncate_text "$clean" 1000)"
      ok_results+=("${server} -> ${clean}")
    fi
  done

  ###########################################################################
  # 2. Incomplete collection (technical issue)
  #
  # FIX:
  #   srv now counts technical failures as well
  ###########################################################################
  if (( ${#technical_errors[@]} > 0 )); then
    local err_str=""
    local ok_str=""
    local srv_tech=0
    local msg

    srv_tech="${#technical_errors[@]}"

    printf -v err_str "%s ; " "${technical_errors[@]}"
    err_str="${err_str% ; }"

    if (( ${#ok_results[@]} > 0 )); then
      printf -v ok_str "%s ; " "${ok_results[@]}"
      ok_str="${ok_str% ; }"
    fi

    msg="CRITICAL: incomplete collection, srv=${srv_tech}"
    [[ -n "$ok_str" ]] && msg+=" | results: ${ok_str}"
    [[ -n "$err_str" ]] && msg+=" | diff: ${err_str}"

    echo "${msg} | srv=${srv_tech};1;2;0 defs=0;1;2;0 engines=0;1;2;0"
    exit "$CRITICAL"
  fi

  ###########################################################################
  # 3. Reference server
  ###########################################################################
  ref="${SERVERS[0]}"
  ref_defs="${SERVER_DEFS[$ref]}"
  ref_eng="${SERVER_ENGINES[$ref]}"
  ref_rc="${SERVER_RC[$ref]}"

  ###########################################################################
  # 4. Global analysis
  ###########################################################################
  srv=0
  has_warn=0
  has_crit=0
  diff=()

  for srv in "${SERVERS[@]:1}"; do

    if [[ "${SERVER_DEFS[$srv]}" != "$ref_defs" || "${SERVER_ENGINES[$srv]}" != "$ref_eng" ]]; then
      ((srv++))
      diff+=("$srv -> $(clean_status_text "${SERVER_RAW[$srv]}")")
    fi

    case "${SERVER_RC[$srv]}" in
      1) has_warn=1 ;;
      2) has_crit=1 ;;
    esac
  done

  (( ${#diff[@]} > 0 )) && printf -v diff_str "%s ; " "${diff[@]}"
  diff_str="${diff_str% ; }"

  ###########################################################################
  # 5. Final decision
  ###########################################################################

  if (( has_crit == 1 )); then
    echo "CRITICAL: srv=$srv | diff: $diff_str | srv=$srv;1;2;0 defs=$ref_defs;1;2;0 engines=$ref_eng;1;2;0"
    exit "$CRITICAL"
  fi

  if (( srv >= 1 )); then
    echo "WARNING: srv=$srv | diff: $diff_str | srv=$srv;1;2;0 defs=$ref_defs;1;2;0 engines=$ref_eng;1;2;0"
    exit "$WARNING"
  fi

  if (( has_warn == 1 )); then
    echo "WARNING: srv=0, defs=$ref_defs, engines=$ref_eng | $(clean_status_text "${SERVER_RAW[$ref]}") | srv=0;1;2;0 defs=$ref_defs;1;2;0 engines=$ref_eng;1;2;0"
    exit "$WARNING"
  fi

  echo "OK: srv=0, defs=$ref_defs, engines=$ref_eng | srv=0;1;2;0 defs=$ref_defs;1;2;0 engines=$ref_eng;1;2;0"
  exit "$OK"
}

main "$@"
