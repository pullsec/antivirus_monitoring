#!/usr/bin/env bash

###############################################################################
# Script: av_snmp.sh
#
# Purpose:
#   Centreon poller-side wrapper used to query a remote SNMP extend entry.
#
# Role:
#   - executed by Centreon on the poller
#   - queries the jump server through SNMP
#   - retrieves the full output of the remote extend script
#   - retrieves the associated return code
#   - returns a Centreon/Nagios-compatible result
#
# Architecture:
#   Centreon -> Poller -> SNMP -> Jump Server -> SNMP Extend -> SAVI script
#
# History / Fixes:
#   - v1: basic SNMP extend query
#   - v2: added token-to-OID conversion
#   - v3: FIX: explicit UNKNOWN when output or return code is missing
#   - v4: FIX: avoids exposing SNMP errors directly in Centreon output
#   - v5: improved comments for maintainability
#
# Notes:
#   - This script does NOT perform the AV checks itself.
#   - It only retrieves the result from the SNMP extend entry.
#   - Centreon status is driven by the exit code returned by this script.
###############################################################################

set -euo pipefail

###############################################################################
# Input parameters
###############################################################################
# HOST:
#   Target jump server IP or hostname.
#
# COMMUNITY:
#   SNMP v2c community configured on the jump server.
#
# TOKEN:
#   SNMP extend token name configured on the jump server.
#
# Example:
#   ./av_snmp.sh 10.10.10.5 public check_av_savi
###############################################################################
HOST="${1:?missing host}"
COMMUNITY="${2:?missing community}"
TOKEN="${3:?missing extend token}"

###############################################################################
# SNMP OIDs - NET-SNMP-EXTEND-MIB
###############################################################################
# These OIDs must match the NET-SNMP-EXTEND-MIB entries used to retrieve:
#   - full script output
#   - script return code
#
# NOTE:
#   Replace the placeholder OIDs with the real OIDs used in your environment.
###############################################################################
OID_OUTPUT_BASE=".1.3.6.1.4.1.XXXX.X.X.X.X.X.X"
OID_RESULT_BASE=".1.3.6.1.4.1.XXXX.X.X.X.X.X.Y"

###############################################################################
# Function: token_to_oid_suffix
#
# Purpose:
#   Convert a textual SNMP extend token into a numeric OID suffix.
#
# Why:
#   SNMP indexed values are addressed using numeric OID suffixes.
#
# Example:
#   token: check_av_savi
#
#   becomes:
#   <length>.<ascii_code_1>.<ascii_code_2>...
#
# FIX:
#   Avoids hardcoding the token OID suffix manually.
###############################################################################
token_to_oid_suffix() {
  local s="$1"
  local len="${#s}"
  local out="$len"
  local i c

  for (( i=0; i<len; i++ )); do
    c=$(printf '%d' "'${s:i:1}")
    out="${out}.${c}"
  done

  printf '%s\n' "$out"
}

SUFFIX="$(token_to_oid_suffix "$TOKEN")"

###############################################################################
# SNMP queries
###############################################################################
# FIX:
#   "|| true" is used to prevent set -e from stopping the script immediately.
#   Validation is handled explicitly below so we can return a clean UNKNOWN.
###############################################################################
OUTPUT="$(
  snmpget -v2c \
          -c "$COMMUNITY" \
          -On \
          "$HOST" \
          "${OID_OUTPUT_BASE}.${SUFFIX}" \
          -Oqv 2>/dev/null || true
)"

RC="$(
  snmpget -v2c \
          -c "$COMMUNITY" \
          -On \
          "$HOST" \
          "${OID_RESULT_BASE}.${SUFFIX}" \
          -Oqv 2>/dev/null || true
)"

###############################################################################
# Validation
###############################################################################
# FIX:
#   If SNMP does not return output or return code, we return UNKNOWN.
#   This usually indicates:
#     - SNMP issue
#     - wrong community
#     - wrong extend token
#     - missing extend configuration
#     - unreachable jump server
###############################################################################
if [[ -z "$OUTPUT" || -z "$RC" ]]; then
  echo "UNKNOWN: unable to retrieve extend '${TOKEN}' from ${HOST}"
  exit 3
fi

###############################################################################
# Return code cleanup
###############################################################################
# FIX:
#   Some SNMP outputs may include unexpected formatting.
#   Keep only the first numeric-looking value.
###############################################################################
RC="$(awk '{print $1}' <<< "$RC")"

if [[ ! "$RC" =~ ^[0-9]+$ ]]; then
  echo "UNKNOWN: invalid return code for extend '${TOKEN}' from ${HOST}: ${RC}"
  exit 3
fi

###############################################################################
# Output handling
###############################################################################
# The remote script already returns a Centreon/Nagios-compatible line:
#   STATUS: message | perfdata
###############################################################################
echo "$OUTPUT"

###############################################################################
# Exit handling
###############################################################################
# Centreon determines the service state from the exit code.
###############################################################################
exit "$RC"
