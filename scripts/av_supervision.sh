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
# Codes Centreon
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

# Seuils: 
# - warning si total > WARNING_THRESHOLD
# - critical si total > CRITICAL_THRESHOLD
WARNING_THRESHOLD=0
CRITICAL_THRESHOLD=1

CURL_TIMEOUT=15
BASE_AV_DIR="/path/path/path/path/path/av"
LOG_DIR="/path/path/log"

# Debug
VERBOSE=0

# URL test/debug
URL_OVERRIDE=""

URL_PATH1="x.x-enka-antivirus/"
URL_PATH2="x.x-enka-antivirus.tar/"
WORD_KEY="enka"
INTEGRATION_SERVER="server4"

# fix: on ne recupere plus via $(fonction), 
# on recupere des variables globales pour conserver les logs verboses
DEF_COUNT=0
ENGINE_COUNT=0

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

declare -a OUTDATED_DEFS=()
declare -a OUTDATED_ENGINES=()

#######################################
# Usage
#######################################
usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]

Options:
  -w <int>    seuil warning (default: 0)
  -c <int>    seuil critical (default: 0)
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

# verbose sur stderr, pour ne pas polluer le message plugin
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
# Fonctions
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
    find "$LOG_DIR" -type f -name "${SCRIPT_NAME}_*" -mtime +15 -delete 2>/dev/null || true
  fi
}

#######################################
# Args
#######################################
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

#######################################
# Controles arguments
#######################################

# fix: on evite les erreurs de saisie des le demarrage
validate_number "$WARNING_THRESHOLD" || die "$UNKNOWN" "UNKNOWN: warning threshold invalide"
validate_number "$CRITICAL_THRESHOLD" || die "$UNKNOWN" "UNKNOWN: critical threshold invalide"
validate_number "$CURL_TIMEOUT" || die "$UNKNOWN" "UNKNOWN: timeout invalide"

if (( WARNING_THRESHOLD > CRITICAL_THRESHOLD )); then
  die "$UNKNOWN" "UNKNOWN: warning threshold > critical threshold"
fi

if [[ -n "$URL_OVERRIDE" ]]; then
  validate_url "$URL_OVERRIDE" || die "$UNKNOWN" "UNKNOWN: URL override invalide"
fi

#######################################
# Init logs
#######################################
init_log
trap cleanup_old_logs EXIT

# fix: evite une deuxieme execution ecrase le contexte de la premiere
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

# fix: data http
#     - curl -> timeout
#     - fail sur erreur http
#     - concatenation 2 sources dans un fichier temporaire 
# recuperation des donnees defs via HTTP
fetch_data() {
  local url="$1"
  local tmp="$2"

  log "Fetch HTTP: ${url}${URL_PATH1}"
  curl -fsS --connect-timeout 5 --max-time "$CURL_TIMEOUT" "${url}${URL_PATH1}" > "$tmp"

  printf '\n' >> "$tmp"

  log "Fetch HTTP: ${url}${URL_PATH2}"
  curl -fsS --connect-timeout 5 --max-time "$CURL_TIMEOUT" "${url}${URL_PATH2}" >> "$tmp"
}

# depend du format de la page (parsings des desfs)
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

#Comparaison base sur la date du jour, 
#les mise a jours sont frequentes (plusieurs fois/jours)

# fix : fonction qui ne retourne plus le compteur via echo
check_defs() {
  local data="$1"
  local today
  today="$(date '+%Y-%m-%d')"

  DEF_COUNT=0
  OUTDATED_DEFS=()

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    local name date_found
    name="$(awk '{print $1}' <<< "$line")"
    date_found="$(awk '{print $2}' <<< "$line")"

    if [[ -z "$name" || -z "$date_found" ]]; then
      log "DEF ignorée (ligne illisible): $line"
      continue
    fi

    if [[ "$date_found" != "$today" ]]; then
      ((DEF_COUNT+=1))
      OUTDATED_DEFS+=("${name}:${date_found}")
      log "OUTDATED DEF: ${name} (${date_found})"
    else
      log "DEF OK: ${name} (${date_found})"
    fi
  done <<< "$data"
}

#######################################
# Check engines 
######################################

# tolerence de  48h , 
# verifie les les moteurs via le ficheirs MANIFEST

#extraction timestamp present sur le MANIFEST, puis selection du plus recent

# fix: avant on prenais head -1 ou tail -1 mais le timestamp  etais aleatoire
#      evite les erreurs liees a l'ordre de ligne 
check_engines() {
  ENGINE_COUNT=0
  OUTDATED_ENGINES=()

  [[ -d "$BASE_AV_DIR" ]] || die "$UNKNOWN" "UNKNOWN: repertoire absent: $BASE_AV_DIR"

  local threshold_date
  threshold_date="$(date --date='2 day ago' '+%Y%m%d')"

  local d
# fix: L'option de shell nullglob controle le Bash mappe les motifs glob qui ne correspondent pas
  shopt -s nullglob
  for d in "$BASE_AV_DIR"/*; do
    [[ -d "$d" ]] || continue

    local engine
    engine="$(basename "$d")"

    # Adapter ce chemin si nécessaire
    local manifest="${d}/path/MANIFEST.txt"

    if [[ ! -f "$manifest" ]]; then
      log "ENGINE ${engine}: manifest absent (${manifest})"
      OUTDATED_ENGINES+=("${engine}:manifest_absent")
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
      OUTDATED_ENGINES+=("${engine}:timestamp_introuvable")
      ((ENGINE_COUNT+=1))
      continue
    fi

    if [[ ! "$ts" =~ ^[0-9]+$ ]]; then
      log "ENGINE ${engine}: timestamp invalide (${ts})"
      OUTDATED_ENGINES+=("${engine}:timestamp_invalide")
      ((ENGINE_COUNT+=1))
      continue
    fi

    local date_found
    date_found="$(date -d "@$ts" '+%Y%m%d')"

    log "ENGINE ${engine}: ts=${ts}, date=${date_found}, threshold=${threshold_date}"

    if [[ "$date_found" -lt "$threshold_date" ]]; then
      log "ENGINE ${engine}: obsolete (${date_found})"
      OUTDATED_ENGINES+=("${engine}:${date_found}")
      ((ENGINE_COUNT+=1))
    else
      log "ENGINE ${engine}: OK (${date_found})"
    fi
  done
  shopt -u nullglob
}

#######################################
# Build status
#######################################

# determine le status final plugin (OK/WARNING/CRITICAL)
# en fonction des annomalie detectes
# CENTREON se base uniquement sur celle -ci

build_status() {
  local total="$1"

  if [[ "$SRV" == "$INTEGRATION_SERVER" ]]; then
    if (( total == 0 )); then
      PLUGIN_STATUS="OK"
      PLUGIN_CODE=$OK
      return 0
    fi

    if (( total > CRITICAL_THRESHOLD )); then
      PLUGIN_STATUS="WARNING"
      PLUGIN_CODE=$WARNING
      return 0
    fi

    if (( total > WARNING_THRESHOLD )); then
      PLUGIN_STATUS="WARNING"
      PLUGIN_CODE=$WARNING
      return 0
    fi
  fi

  if (( total == 0 )); then
    PLUGIN_STATUS="OK"
    PLUGIN_CODE=$OK
  elif (( total > CRITICAL_THRESHOLD )); then
    PLUGIN_STATUS="CRITICAL"
    PLUGIN_CODE=$CRITICAL
  elif (( total > WARNING_THRESHOLD )); then
    PLUGIN_STATUS="WARNING"
    PLUGIN_CODE=$WARNING
  else
    PLUGIN_STATUS="OK"
    PLUGIN_CODE=$OK
  fi
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
# fix: le fichier temporaire est supprime en sortie
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

# perfdata centreon a ajouter si necessaire 
#| defs=${defs} engines=${engines}
#  echo ${PLUGIN_STATUS}: defs=${defs}, engines=${engines} 

# Fournir le diagnostique directement  exploitable
# pas de necessite connexion SSH
  MSG="${PLUGIN_STATUS}: defs=${defs}, engines=${engines}"

  if ((defs > 0 )); then
    printf -v DEF_STR "%s, ""${OUTDATED_DEFS[@]}"
    DEF_STR="${DEF_STR%, }"
    MSG+=" | Defs KO: ${DEF_STR}"
  fi

  if ((engines > 0 )); then
    printf -v ENG_STR "%s, ""${OUTDATED_ENGINES[@]}"
    ENG_STR="${ENG_STR%, }"
    MSG+=" | Engines KO: ${ENG_STR}"
  fi
 
# label=value;warn;crit;min
# permet l'exploitation dans centreon (graph/historique)

   echo "$MSG | defs=${defs};1;2;0
   engines=${engines};1;2;0"

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

# le code retour determine le status CENTREON,
# le message seul n'est pas utilise pour le status

  log "Fin ${SCRIPT_NAME} sur ${SRV} (${PLUGIN_STATUS})"
  exit "$PLUGIN_CODE"
}

main "$@"
