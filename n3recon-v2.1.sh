#!/usr/bin/env bash
# n3recon-v2.1.sh - Modified for Output Flag and API Key Rotation

set -o errexit
set -o nounset
set -o pipefail


#--------------temporary fix command ---------------
# Unalias tools that often conflict with local aliases
if alias gf >/dev/null 2>&1; then
  unalias gf || true
fi
if alias gau >/dev/null 2>&1; then
  unalias gau || true
fi

# ----------------- DEFAULTS -----------------
THREADS=${THREADS:-200}
# CHANGE 1: Default output root is now the current directory (.)
OUT_ROOT=${OUT_ROOT:-.}
SKIP_SCREENSHOTS=false
ONLY_SUBDOMAINS=false
RESUME=false
NEW_RUN=false
RECURSIVE=false
SKIP_VULN_SCAN=false
SKIP_DIR_FUZZ=false
DOMAINS_FILE=""
EXCLUDE_ARG=""
WHITELIST_ARG=""
API_KEYS_FILE=""
WORDLIST=""
DOMAINS=()

# --- TOOL PATHS (Auto-detected - no hardcoded paths) ---
# Tools are auto-detected using 'has' command. Optional tools will be skipped if not found.


# ----------------- HELPERS -----------------
has() { command -v "$1" >/dev/null 2>&1; }
log() { echo "[$(date +"%Y-%m-%d %H:%M:%S")] $*" | tee -a "${LOG:-/dev/null}"; }

usage(){ cat <<'USG'
n3recon-v2.1.sh - for ultimate recon - pipeline with extensive tools - created by @n3dir
Usage: ./n3recon-v2.1.sh [domain ...] [options]
Options:
  --domains-file FILE        Read domains from text file (one per line)
  --output-dir DIR           Set the root directory for all output (Default: .)
  --resume                   Resume from latest run for each target (if exists)
  --new                      Force a new run (ignore resume)
  --threads N                Number of parallel threads (default 200)
  --exclude file_or_list     Comma-separated strings OR file path to exclude
  --whitelist file_or_list   Comma-separated strings OR file path to whitelist (keep only matches)
  --only-subdomains          Stop after subdomain enumeration + filtering
  --skip-screenshots         Skip screenshot stage
  --skip-vuln-scan           Skip vulnerability scanning with nuclei
  --skip-dir-fuzz            Skip directory fuzzing with ffuf
  --recursive-subdomains     Use more aggressive subdomain enumeration (brute, recursive, permutations)
  --api-keys-file FILE       Path to API keys config file. API key values can be comma-separated for rotation.
  --wordlist FILE            Path to wordlist for brute force and dir fuzzing (default: assume common.txt)
  -h, --help                 Show this help
USG
 exit 1; }

parse_list_arg(){
  local arg="$1"
  if [ -z "$arg" ]; then return 0; fi
  if [ -f "$arg" ]; then sed 's/^\s\+//;s/\s\+$//' "$arg" | sed '/^$/d'
  else echo "$arg" | tr ',' '\n' | sed 's/^\s\+//;s/\s\+$//' | sed '/^$/d'
  fi
}

apply_exclude(){ local file="$1"; local exclude_arg="$2"; [ -f "$file" ] || return 0; [ -z "$exclude_arg" ] && return 0
  local tmpf; tmpf=$(mktemp)
  if [ -f "$exclude_arg" ]; then grep -v -F -f "$exclude_arg" "$file" > "$tmpf" || true
  else local patterns; patterns=$(parse_list_arg "$exclude_arg" | sed 's/[]\[\.\*^$/]/\\&/g' | paste -sd '|' -)
       [ -z "$patterns" ] && cp "$file" "$tmpf" || grep -v -E "$patterns" "$file" > "$tmpf" || true
  fi
  mv "$tmpf" "$file"
}

apply_whitelist(){ local file="$1"; local whitelist_arg="$2"; [ -f "$file" ] || return 0; [ -z "$whitelist_arg" ] && return 0
  local tmpf; tmpf=$(mktemp)
  if [ -f "$whitelist_arg" ]; then grep -F -f "$whitelist_arg" "$file" > "$tmpf" || true
  else local patterns; patterns=$(parse_list_arg "$whitelist_arg" | sed 's/[]\[\.\*^$/]/\\&/g' | paste -sd '|' -)
       [ -z "$patterns" ] && cp "$file" "$tmpf" || grep -E "$patterns" "$file" > "$tmpf" || true
  fi
  mv "$tmpf" "$file"
}

get_next_run_id() {
  local target_base_dir="$1"
  local max_run=0
  
  # Find the highest run number across ALL existing directories
  for dir in "$target_base_dir"/*; do
    if [[ -d "$dir" && "$(basename "$dir")" =~ run([0-9]+)$ ]]; then
      run_num=${BASH_REMATCH[1]}
      if (( run_num > max_run )); then
        max_run=$run_num
      fi
    fi
  done
  
  echo $((max_run + 1))
}

get_latest_run_dir() {
  local target_base_dir="$1"
  local latest_dir=""
  local latest_mtime=0
  
  # Find the most recently modified run directory
  for dir in "$target_base_dir"/*; do
    if [[ -d "$dir" && "$(basename "$dir")" =~ run[0-9]+$ ]]; then
      mtime=$(stat -c %Y "$dir" 2>/dev/null || stat -f %m "$dir" 2>/dev/null || echo 0)
      if (( mtime > latest_mtime )); then
        latest_mtime=$mtime
        latest_dir="$dir"
      fi
    fi
  done
  
  echo "$latest_dir"
}

setup_go_env(){ if has go; then
  GOPATH=$(go env GOPATH 2>/dev/null || echo "$HOME/go")
  GOBIN=$(go env GOBIN 2>/dev/null || echo "$GOPATH/bin")
  export GOPATH GOBIN
  mkdir -p "$GOBIN" || true
  case ":$PATH:" in *":$GOBIN:") ;; *) export PATH="$PATH:$GOBIN" ;; esac
  if [ -d /snap/bin ]; then case ":$PATH:" in *":/snap/bin:") ;; *) export PATH="$PATH:/snap/bin" ;; esac; fi
fi
}

safe_run(){ log "RUN: $*"; if ! eval "$@" >>"${LOG}" 2>&1; then log "WARN: command failed: $*"; fi }

# CHANGE 2: Load API configs to handle comma-separated keys for rotation
load_api_configs() {
  if [ -n "$API_KEYS_FILE" ] && [ -f "$API_KEYS_FILE" ]; then
    # For subfinder, we still point to the config file (it handles its own logic)
    export SUBFINDER_CONFIG="$API_KEYS_FILE"
    
    # Read all keys for rotation
    if has yq; then
      # If yq is present, try to read comma-separated keys for chaos and securitytrails
      export ALL_CHAOS_KEYS=$(yq e '.chaos // empty' "$API_KEYS_FILE" 2>/dev/null | tr -d ' ' || true)
      export ALL_SECURITYTRAILS_KEYS=$(yq e '.securitytrails // empty' "$API_KEYS_FILE" 2>/dev/null | tr -d ' ' || true)
    else
      # Fallback for grep (assumes single line format: key: value1,value2,value3)
      export ALL_CHAOS_KEYS=$(grep 'chaos:' "$API_KEYS_FILE" | awk '{print $2}' | tr -d ' ' || true)
      export ALL_SECURITYTRAILS_KEYS=$(grep 'securitytrails:' "$API_KEYS_FILE" | awk '{print $2}' | tr -d ' ' || true)
    fi
  fi
}

# CHANGE 2: Function to iterate through keys until success
run_with_key_rotation() {
    local tool_name="$1"
    local key_var_name="$2" # e.g., ALL_CHAOS_KEYS
    local command_template="$3" # e.g., "chaos -d $TARGET -key KEY_PLACEHOLDER -o $OUTDIR/subdomains/chaos.txt"
    
    local keys_list
    local key_index=0
    
    # Get the comma-separated list of keys from the exported environment variable
    eval "keys_list=\"\$$key_var_name\""
    
    if [ -z "$keys_list" ]; then
        log "WARN: No keys found for $tool_name. Skipping."
        return 1
    fi

    log "Attempting $tool_name with key rotation..."
    
    IFS=',' read -r -a keys_array <<< "$keys_list"

    for current_key in "${keys_array[@]}"; do
        if [ -n "$current_key" ]; then
            log "Trying key index $key_index for $tool_name..."
            
            # Substitute the current key into the command template
            local cmd
            cmd=$(echo "$command_template" | sed "s/KEY_PLACEHOLDER/$current_key/")

            # Run the command and capture success
            if safe_run "$cmd"; then
                log "$tool_name succeeded with key index $key_index."
                return 0 # Success
            fi
            key_index=$((key_index + 1))
        fi
    done

    log "ERROR: $tool_name failed with all provided keys."
    return 1 # Failure
}

# ----------------- ARG PARSING -----------------
if [ "$#" -eq 0 ]; then usage; fi
ARGS=("$@")
idx=0
while [ $idx -lt ${#ARGS[@]} ]; do
  a=${ARGS[$idx]}
  case "$a" in
    --domains-file) idx=$((idx+1)); DOMAINS_FILE=${ARGS[$idx]:-} ;;
    --output-dir) idx=$((idx+1)); OUT_ROOT=${ARGS[$idx]:-.} ;; # CHANGE 1
    --resume) RESUME=true ;;
    --new) NEW_RUN=true ;;
    --threads) idx=$((idx+1)); THREADS=${ARGS[$idx]:-200} ;;
    --exclude) idx=$((idx+1)); EXCLUDE_ARG=${ARGS[$idx]:-} ;;
    --whitelist) idx=$((idx+1)); WHITELIST_ARG=${ARGS[$idx]:-} ;;
    --only-subdomains) ONLY_SUBDOMAINS=true ;;
    --skip-screenshots) SKIP_SCREENSHOTS=true ;;
    --skip-vuln-scan) SKIP_VULN_SCAN=true ;;
    --skip-dir-fuzz) SKIP_DIR_FUZZ=true ;;
    --recursive-subdomains) RECURSIVE=true ;;
    --api-keys-file) idx=$((idx+1)); API_KEYS_FILE=${ARGS[$idx]:-} ;;
    --wordlist) idx=$((idx+1)); WORDLIST=${ARGS[$idx]:-} ;;
    -h|--help) usage ;;
    --*) echo "Unknown option: $a"; usage ;;
    *) DOMAINS+=("$a") ;;
  esac
  idx=$((idx+1))
done

if [ -n "$DOMAINS_FILE" ]; then
  if [ -f "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
      d=$(echo "$d" | sed 's/^\s\+//;s/\s\+$//'); [ -z "$d" ] && continue; DOMAINS+=("$d")
    done < "$DOMAINS_FILE"
  else
    echo "Domains file not found: $DOMAINS_FILE"; exit 1
  fi
fi

[ ${#DOMAINS[@]} -eq 0 ] && { echo "No domains specified"; usage; }

setup_go_env
load_api_configs

# Default wordlist if not provided - try common locations
if [ -z "$WORDLIST" ]; then
  # Try multiple common wordlist locations
  for candidate in "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt" \
                   "/usr/share/wordlists/common.txt" \
                   "/opt/SecLists/Discovery/Web-Content/common.txt" \
                   "./wordlists/common.txt"; do
    if [ -f "$candidate" ]; then
      WORDLIST="$candidate"
      break
    fi
  done
  if [ -z "$WORDLIST" ]; then
    log "WARN: Wordlist not provided and no default found. Directory fuzzing/brute force will be skipped unless wordlist is provided."
  fi
fi

# ----------------- MAIN LOOP -----------------
for TARGET in "${DOMAINS[@]}"; do
  TARGET=$(echo "$TARGET" | sed 's#^https\?://##; s#/$##')
  TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
  # CHANGE 1: OUT_ROOT is now defined by the flag
  TARGET_BASE_DIR="${OUT_ROOT%/}/pipeline/UltimateRecon/results/${TARGET}"
  mkdir -p "$TARGET_BASE_DIR"

  # Determine output directory with GLOBAL incremental run ID
  if $RESUME && ! $NEW_RUN; then
    LATEST_RUN_DIR=$(get_latest_run_dir "$TARGET_BASE_DIR")
    if [ -n "$LATEST_RUN_DIR" ]; then
      OUTDIR="$LATEST_RUN_DIR"
      RUN_ID=$(basename "$OUTDIR" | sed 's/.*run//')
      log "Resuming latest run: $OUTDIR (Global Run $RUN_ID)"
    else
      # No existing runs, create run1
      RUN_ID=$(get_next_run_id "$TARGET_BASE_DIR")
      OUTDIR="$TARGET_BASE_DIR/run${RUN_ID}"
      mkdir -p "$OUTDIR"
      log "No previous runs found, creating first run: $OUTDIR"
    fi
  elif $NEW_RUN; then
    # Force new run with next global incremental ID
    RUN_ID=$(get_next_run_id "$TARGET_BASE_DIR")
    OUTDIR="$TARGET_BASE_DIR/run${RUN_ID}"
    mkdir -p "$OUTDIR"
    log "NEW_RUN forced, creating new global run: $OUTDIR (Run $RUN_ID)"
  else
    # Normal new run with next global incremental ID
    RUN_ID=$(get_next_run_id "$TARGET_BASE_DIR")
    OUTDIR="$TARGET_BASE_DIR/run${RUN_ID}"
    mkdir -p "$OUTDIR"
    log "Creating new global run: $OUTDIR (Run $RUN_ID)"
  fi

  LOG="$OUTDIR/pipeline.log"
  # figlet "n3recon" | tee -a "$LOG" # Commented out, figlet is an optional dependency
  echo "_created by me(n3dir)----v3" | tee -a "$LOG"
  echo "==== Ultimate Recon Using n3recon-v3 run for $TARGET - Global Run $RUN_ID @ $TIMESTAMP ====" | tee -a "$LOG"
  echo "Full directory: $OUTDIR" | tee -a "$LOG"
  mkdir -p "$OUTDIR/subdomains" "$OUTDIR/resolved" "$OUTDIR/alive" "$OUTDIR/ports" "$OUTDIR/urls" "$OUTDIR/params" "$OUTDIR/vulns" "$OUTDIR/js" "$OUTDIR/tls" "$OUTDIR/osint" "$OUTDIR/directories" "$OUTDIR/secrets" "$OUTDIR/screenshots" "$OUTDIR/notes"
  NOTES="$OUTDIR/notes/notes.txt"
  RUN_INFO="$OUTDIR/notes/run_info.txt"
  
  # Create run info file (using the new $OUT_ROOT value)
  cat > "$RUN_INFO" << EOF
Global Run ID: $RUN_ID
Timestamp: $TIMESTAMP
Target: $TARGET
Output Root: $OUT_ROOT
Directory: $OUTDIR
Command: $0 ${*@Q}
Threads: $THREADS
Recursive: $([ "$RECURSIVE" = true ] && echo "yes" || echo "no")
Resume: $([ "$RESUME" = true ] && echo "yes (from run $RUN_ID)" || echo "no")
New Run: $([ "$NEW_RUN" = true ] && echo "yes" || echo "no")
API Keys: $([ -n "$API_KEYS_FILE" ] && echo "yes ($API_KEYS_FILE) - Key Rotation Enabled" || echo "no")
Wordlist: $([ -n "$WORDLIST" ] && echo "$WORDLIST" || echo "Not Provided/Found")
Started: $(date -u +'%Y-%m-%dT%H:%M:%SZ')

Previous runs for this target:
$(ls -1t "$TARGET_BASE_DIR"/run* 2>/dev/null | nl -nrz | sed 's/^/  /' || echo "  None")
EOF

  echo "target: $TARGET" > "$NOTES"
  echo "global_run_id: $RUN_ID" >> "$NOTES"
  echo "timestamp: $TIMESTAMP" >> "$NOTES"
  echo "started: $(date -u +'%Y-%m-%dT%H:%M:%SZ')" >> "$NOTES"

  SUBS_ALL="$OUTDIR/subdomains/all.txt"
  RESOLVED="$OUTDIR/resolved/dnsx.txt"
  IPS_ALL="$OUTDIR/resolved/ips.txt"
  ALIVE="$OUTDIR/alive/httpx.txt"
  PORTS_OPEN="$OUTDIR/ports/naabu.txt"
  URLS_ALL="$OUTDIR/urls/all.txt"
  URLS_FILTERED="$OUTDIR/urls/filtered.txt"
  PARAMS_FUZZ="$OUTDIR/params/for_fuzz.txt"
  VULNS_NUCLEI="$OUTDIR/vulns/nuclei.txt"
  
  JS_DIR="$OUTDIR/js"
  JS_FILES="$JS_DIR/files.txt"
  JS_URLS_RAW="$JS_DIR/raw_js_urls.txt"
  JS_URLS_ALIVE="$JS_DIR/alive_js_urls.txt"
  JS_FILES_DOWNLOADED="$JS_DIR/downloaded_files.txt"
  JS_CONTENT_DIR="$JS_DIR/content"
  JS_CONTENT_BEAUTIFIED="$JS_DIR/beautified"
  JS_HASH_MAP="$JS_CONTENT_DIR/hash_map.txt"

  SECRETS="$OUTDIR/secrets/all.txt"
  SECRETS_SECRETFINDER="$OUTDIR/secrets/secretfinder.txt"
  URLS_LINKFINDER="$OUTDIR/urls/linkfinder.txt" 

  TLS_INFO="$OUTDIR/tls/tlsx.txt"
  OSINT_EMAILS="$OUTDIR/osint/emails.txt"
  DIRS_FOUND="$OUTDIR/directories/ffuf.txt"

  # ----------------- SUBDOMAIN ENUM -----------------
  if [ ! -s "$SUBS_ALL" ] || ! $RESUME || $NEW_RUN; then
    log "Enumerating subdomains for $TARGET with ultimate tools (Global Run $RUN_ID)"
    > "$SUBS_ALL"

    # Project Discovery: subfinder (Uses SUBFINDER_CONFIG environment variable)
    if has subfinder; then
      safe_run "subfinder -d $TARGET -all -recursive=$RECURSIVE -t $THREADS -silent -o $OUTDIR/subdomains/subfinder.txt"
    fi

    # Amass
    if has amass; then
      safe_run "amass enum -passive -d $TARGET -o $OUTDIR/subdomains/amass_passive.txt"
      if $RECURSIVE; then
        safe_run "amass enum -brute -d $TARGET -o $OUTDIR/subdomains/amass_brute.txt"
      else
        safe_run "amass enum -active -d $TARGET -o $OUTDIR/subdomains/amass_active.txt"
      fi
    fi

    # Assetfinder
    if has assetfinder; then
      safe_run "assetfinder --subs-only $TARGET > $OUTDIR/subdomains/assetfinder.txt"
    fi

    # Findomain
    if has findomain; then
      safe_run "findomain -t $TARGET -u $OUTDIR/subdomains/findomain.txt -q" || true
    fi

    # Sublist3r
    if has sublist3r; then
      safe_run "sublist3r -d $TARGET -t $THREADS -o $OUTDIR/subdomains/sublist3r.txt"
    fi

    # Chaos (CHANGE 2: Use rotation function)
    if has chaos && [ -n "${ALL_CHAOS_KEYS:-}" ]; then
      run_with_key_rotation "chaos" "ALL_CHAOS_KEYS" "chaos -d $TARGET -key KEY_PLACEHOLDER -o $OUTDIR/subdomains/chaos.txt"
    fi

    # Uncover
    if has uncover; then
      safe_run "uncover -q 'domain:*.$TARGET' -l 10000 -o $OUTDIR/subdomains/uncover.txt"
    fi

    # Crt.sh
    if has curl && has jq; then
      curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/^\*\.//' | sort -u > "$OUTDIR/subdomains/crtsh.txt" || true
    fi

    # Github-subdomains
    if has github-subdomains; then
      safe_run "github-subdomains -d $TARGET -o $OUTDIR/subdomains/github.txt"
    fi

    # SubDomainizer
    if has subdomainizer; then
      safe_run "subdomainizer -u https://$TARGET -o $OUTDIR/subdomains/subdomainizer.txt"
    fi

    # Crobat
    if has crobat; then
      safe_run "crobat -s $TARGET >> $OUTDIR/subdomains/crobat.txt"
    fi

    # Certspotter
    if has curl && has jq; then
      curl -s "https://certspotter.com/api/v0/certs?domain=$TARGET" | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u > "$OUTDIR/subdomains/certspotter.txt" || true
    fi

    # Bufferover
    if has curl && has jq; then
      curl -s "https://dns.bufferover.run/dns?q=.$TARGET" | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u > "$OUTDIR/subdomains/bufferover.txt" || true
    fi

    # Riddler
    if has curl; then
      curl -s "https://riddler.io/search/exportcsv?q=pld:$TARGET" | grep -Po "(([\w.-]*)\.${TARGET})" | sort -u > "$OUTDIR/subdomains/riddler.txt" || true
    fi

    # SecurityTrails (CHANGE 2: Use rotation function)
    if [ -n "${ALL_SECURITYTRAILS_KEYS:-}" ] && has curl && has jq; then
      # Need to adjust the template to ensure curl/jq works, replacing $TARGET correctly
      # The API call returns JSON which needs jq parsing
      run_with_key_rotation "SecurityTrails" "ALL_SECURITYTRAILS_KEYS" 'curl -s "https://api.securitytrails.com/v1/domain/'"$TARGET"'/subdomains?children_only=false&include_inactive=true" -H "APIKEY: KEY_PLACEHOLDER" | jq -r ".subdomains[] | . + \".\" + \"'"$TARGET"'\"" | sort -u > '$OUTDIR'/subdomains/securitytrails.txt'
    fi

    # Puredns brute if recursive
    if $RECURSIVE && has puredns && [ -f "$WORDLIST" ]; then
      safe_run "puredns bruteforce $WORDLIST $TARGET -t $THREADS -q >>  $OUTDIR/subdomains/puredns_brute.txt"
    fi

    # Dnsgen permutations if recursive
    if $RECURSIVE && has dnsgen && [ -s "$SUBS_ALL" ]; then
      # Must combine and dedupe before using $SUBS_ALL for dnsgen, otherwise it uses old data
      if has anew; then
        for f in $OUTDIR/subdomains/*.txt; do [ -f "$f" ] || continue; cat "$f" | anew "$SUBS_ALL" >/dev/null 2>&1 || true; done
      else
        cat $OUTDIR/subdomains/*.txt 2>/dev/null | sed 's/^\s\+//;s/\s\+$//' | sort -u > "$SUBS_ALL" || true
      fi
      # Now run dnsgen on the updated list
      if [ -s "$SUBS_ALL" ]; then
        cat "$SUBS_ALL" | dnsgen - | sort -u > "$OUTDIR/subdomains/dnsgen_perm.txt" || true
      fi
    fi

    # Combine & dedupe (Final pass)
    if has anew; then
      for f in $OUTDIR/subdomains/*.txt; do [ -f "$f" ] || continue; cat "$f" | anew "$SUBS_ALL" >/dev/null 2>&1 || true; done
    else
      cat $OUTDIR/subdomains/*.txt 2>/dev/null | sed 's/^\s\+//;s/\s\+$//' | sort -u > "$SUBS_ALL" || true
    fi

    apply_exclude "$SUBS_ALL" "$EXCLUDE_ARG"
    apply_whitelist "$SUBS_ALL" "$WHITELIST_ARG"
  fi

  $ONLY_SUBDOMAINS && { log "ONLY_SUBDOMAINS set; ending Global Run $RUN_ID"; echo "finished: $(date -u +'%Y-%m-%dT%H:%M:%SZ')" >> "$NOTES"; continue; }

  # ----------------- DNS RESOLUTION & IP COLLECTION -----------------
  if [ ! -s "$RESOLVED" ] || ! $RESUME || $NEW_RUN; then
    log "Resolving subdomains with dnsx and collecting IPs (Global Run $RUN_ID)"
    if has dnsx && [ -s "$SUBS_ALL" ]; then
      cat "$SUBS_ALL" | dnsx -silent -trace -all -resp -t $THREADS >> "$RESOLVED" || log "dnsx resolution failed"
      if has anew; then
        cat "$RESOLVED" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | anew "$IPS_ALL" || true
      else
        cat "$RESOLVED" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u >> "$IPS_ALL" || true
      fi
    else
      cp "$SUBS_ALL" "$RESOLVED" || true
    fi
  fi

  # ----------------- ASN & IP OSINT -----------------
  if [ ! -s "$OUTDIR/osint/asn.txt" ] || ! $RESUME || $NEW_RUN; then
    if has asnmap && [ -s "$IPS_ALL" ]; then
      safe_run "asnmap -f $IPS_ALL -silent -o $OUTDIR/osint/asn.txt"
    fi
  fi

# ----------------- HTTP(S) PROBE ----------------- V2 -----
  if [ ! -s "$ALIVE" ] || ! $RESUME || $NEW_RUN; then
    log "Probing HTTP(S) endpoints with httpx (checks if sub is alive.) (Global Run $RUN_ID)"
  
    if has httpx && [ -s "$SUBS_ALL" ]; then
      ALIVE_FULL_OUTPUT="$OUTDIR/alive/httpx_raw_full.txt" # Temporary file for full httpx output
    
      # 1. Run httpx once, collecting status codes.
      safe_run "cat $SUBS_ALL | httpx -silent -threads $THREADS -title -status-code -cname -server -o '$ALIVE_FULL_OUTPUT'"
    
      # --- 2. Create Clean ALIVE List for Downstream Tools ---
      if [ -s "$ALIVE_FULL_OUTPUT" ]; then
        log "Creating clean URL list in $ALIVE and filtering by status code."
        
        # Extract ONLY the URL (the first field in httpx -v output) for $ALIVE
        cat "$ALIVE_FULL_OUTPUT" | awk '{print $1}' | sort -u > "$ALIVE"

        # --- 3. Status Code Filtering ---
        cat "$ALIVE_FULL_OUTPUT" | grep '\\[200\\]' | sort -u > "$OUTDIR/alive/200.txt"
        cat "$ALIVE_FULL_OUTPUT" | grep '\\[403\\]' | sort -u > "$OUTDIR/alive/403.txt"
        cat "$ALIVE_FULL_OUTPUT" | grep '\\[302\\]' | sort -u > "$OUTDIR/alive/302.txt"
        
        rm -f "$ALIVE_FULL_OUTPUT"
      fi

    else
      log "httpx not found or no subdomains domains"
    fi
  fi

  apply_exclude "$ALIVE" "$EXCLUDE_ARG"
  apply_whitelist "$ALIVE" "$WHITELIST_ARG"

  # ----------------- TLS PROBING -----------------
  if [ ! -s "$TLS_INFO" ] || ! $RESUME || $NEW_RUN; then
    log "Probing TLS with tlsx (Global Run $RUN_ID)"
    if has tlsx && [ -s "$ALIVE" ]; then
      cat "$ALIVE" | tlsx -san -cn -silent -o "$TLS_INFO" || log "tlsx failed"
    fi
  fi

  # ----------------- PORT SCANNING -----------------
  if [ ! -s "$PORTS_OPEN" ] || ! $RESUME || $NEW_RUN; then
    log "Scanning ports with naabu (Global Run $RUN_ID)"
    if has naabu && [ -s "$SUBS_ALL" ]; then
      safe_run "cat $SUBS_ALL | naabu -p 8080,8888,22,21,433,53,161,500,5900,6667,23,139,5432,3306,27027 -silent -c $THREADS -o "$PORTS_OPEN""
    fi
  fi

  # ----------------- OSINT GATHERING -----------------
  if [ ! -s "$OSINT_EMAILS" ] || ! $RESUME || $NEW_RUN; then
    log "Gathering OSINT with theHarvester (Global Run $RUN_ID)"
    if has theHarvester; then
      # Using 'theHarvester' directly instead of 'uv run' for broader compatibility
      safe_run "theHarvester -d $TARGET -b all -f $OUTDIR/osint/harvester"
      grep -oP '[\w\.-]+@[\w\.-]+' "$OUTDIR/osint/harvester"* | sort -u > "$OSINT_EMAILS" || true
    fi
  fi

  # ----------------- URL COLLECTION & CRAWLING (FIXED: Parallelization) -----------------
  if [ ! -s "$URLS_ALL" ] || ! $RESUME || $NEW_RUN; then
    log "Collecting and crawling URLs with multiple tools (Global Run $RUN_ID) - PARALLEL MODE"
    > "$URLS_ALL"
    
    if [ -s "$ALIVE" ]; then
      ALIVE_HOSTS_LIST="$OUTDIR/alive/hosts_for_crawling.txt"
      # Extract hosts from ALIVE file (which contains URLs)
      cat "$ALIVE" | awk -F'//' '{print $2}' | awk -F'/' '{print $1}' | sort -u > "$ALIVE_HOSTS_LIST"

      if [ -s "$ALIVE_HOSTS_LIST" ]; then
        
        # Start all long-running archive/list tools in the background
        (
          # gau/waybackurls: Use cat + xargs to feed all hosts in parallel
          if has gau; then safe_run "cat $ALIVE_HOSTS_LIST | xargs -I {} -P $THREADS gau --subs {} --retries 3 >> $OUTDIR/urls/gau.txt" & fi
          if has waybackurls; then safe_run "cat $ALIVE_HOSTS_LIST | xargs -I {} -P $THREADS echo {} | waybackurls >> $OUTDIR/urls/wayback.txt" & fi
          
          # katana: Use list mode on all ALIVE hosts (full URLs)
          if has katana; then safe_run "cat $ALIVE | awk '{print \$1}' | katana -list - -d 2 -silent -o $OUTDIR/urls/katana.txt" & fi
          
          # gospider: Use list mode on all ALIVE hosts (full URLs)
          if has gospider; then 
            safe_run "cat $ALIVE | awk '{print \$1}' | gospider -s - -d 2 -c $THREADS -o $OUTDIR/urls/gospider_out" & 
          fi
          
          # hakrawler: Use list mode on all ALIVE hosts
          if has hakrawler; then safe_run "cat $ALIVE | awk '{print \$1}' | hakrawler -s -subs -d 2 >> $OUTDIR/urls/hakrawler.txt" & fi

          wait # Wait for all background collection jobs to complete
        )

        # Combine & dedupe
        if has anew; then
          for f in $OUTDIR/urls/*.txt $OUTDIR/urls/gospider_out/*; do 
            [ -f "$f" ] || continue; 
            cat "$f" | anew "$URLS_ALL" >/dev/null 2>&1 || true; 
          done
        else
          cat $OUTDIR/urls/*.txt $OUTDIR/urls/gospider_out/* 2>/dev/null | sed 's/\r$//' | sort -u > "$URLS_ALL" || true
        fi
        
        # Clean up gospider output directory if created
        rm -rf "$OUTDIR/urls/gospider_out" 2>/dev/null || true
        rm -f "$ALIVE_HOSTS_LIST" 2>/dev/null || true
      fi

      apply_exclude "$URLS_ALL" "$EXCLUDE_ARG"
      apply_whitelist "$URLS_ALL" "$WHITELIST_ARG"
    fi
  fi

  # Filter URLs with uro
  if has uro && [ -s "$URLS_ALL" ]; then
    cat "$URLS_ALL" | uro > "$URLS_FILTERED" || cp "$URLS_ALL" "$URLS_FILTERED"
  else
    cp "$URLS_ALL" "$URLS_FILTERED"
  fi


  # ----------------- JS DISCOVERY & PREPARATION -----------------
  if [ ! -s "$JS_URLS_ALIVE" ] || ! $RESUME || $NEW_RUN; then
    log "Starting advanced JS file discovery and preparation (Global Run $RUN_ID)"
    mkdir -p "$JS_CONTENT_DIR" "$JS_CONTENT_BEAUTIFIED"

    > "$JS_URLS_RAW"

    # --- 1. Katana Discovery (Crawling from all subdomains) ---
    if has katana && [ -s "$SUBS_ALL" ]; then
      log "Running Katana for deep JS collection..."
      KATANA_RAW_OUTPUT="$JS_DIR/katana_raw_output.txt"
      safe_run "katana -list $SUBS_ALL -d 2 -jc -v -t $THREADS -o $KATANA_RAW_OUTPUT"
      if [ -s "$KATANA_RAW_OUTPUT" ]; then
        cat "$KATANA_RAW_OUTPUT" | awk '{for(i=1;i<=NF;i++) if($i ~ /^https?:\/\//) print \$i}' | anew "$JS_URLS_RAW"
        rm -f "$KATANA_RAW_OUTPUT"
      fi
    fi

    # --- 2. Subjs Discovery (Scanning alive hosts) ---
    if has subjs && [ -s "$ALIVE" ]; then
      log "Running subjs on alive hosts for JS endpoint extraction..."
      safe_run "cat $ALIVE | awk '{print \$1}' | subjs -c $THREADS | anew $JS_URLS_RAW"
    fi

    # --- 3. getJS Discovery (Scanning alive hosts) ---
    if has getJS && [ -s "$ALIVE" ]; then
      log "Running getJS on alive hosts for JS endpoint extraction..."
      safe_run "cat $ALIVE | awk '{print \$1}' | getJS --resolve | anew $JS_URLS_RAW"
    fi

    # --- 4. Final Deduplication and Liveness Check ---
    if [ -s "$JS_URLS_RAW" ]; then
      cat "$JS_URLS_RAW" | uro > "$JS_DIR/tmp_dedup.txt" || cp "$JS_URLS_RAW" "$JS_DIR/tmp_dedup.txt"
    
      log "Filtering raw JS URLs for liveness -status 200- with httpx..."
      if has httpx; then
        safe_run "cat $JS_DIR/tmp_dedup.txt | httpx -silent -mc 200 -threads $THREADS -o $JS_URLS_ALIVE"
      else
        cp "$JS_DIR/tmp_dedup.txt" "$JS_URLS_ALIVE"
      fi
      rm -f "$JS_DIR/tmp_dedup.txt"
    fi
  fi

  # ----------------- OFFLINE PREPARATION AND BEAUTIFICATION -----------------
  if [ -s "$JS_URLS_ALIVE" ]; then
    # --- 5. Pull down the JS for offline static analysis ---
    if [ ! -s "$JS_HASH_MAP" ] || $NEW_RUN; then
      log "Downloading and hashing live JS files..."
      > "$JS_HASH_MAP"
    
      while IFS= read -r url; do
          hash=$(printf "%s" "$url" | md5sum | awk '{print $1}')
          echo "$hash $url" >> "$JS_HASH_MAP"
          safe_run "curl -skL --compressed '$url' -o '$JS_CONTENT_DIR/${hash}.js'"
      done < "$JS_URLS_ALIVE"
    fi

    # --- 6. JS Beautifier ---
    if has js-beautify; then
      log "Beautifying collected JS files for easier reading..."
      for f in "$JS_CONTENT_DIR"/*.js; do
        [ -f "$f" ] || continue
        safe_run "js-beautify '$f' -o '$JS_CONTENT_BEAUTIFIED/$(basename "$f")'"
      done
    else
      log "WARN: js-beautify not found. Skipping beautification."
    fi
  fi


  JS_FILES="$JS_URLS_ALIVE"

  # ----------------- SECRET SCANNING & JS LINK ANALYSIS -----------------
  JS_FILES_FOR_SCAN="$JS_CONTENT_DIR"
  SECRETS_GF="$OUTDIR/secrets"
  SECRETS_TRUFFLE="$OUTDIR/secrets/trufflehog.txt"
  SECRETS_SECRETFINDER="$OUTDIR/secrets/secretfinder.txt"
  
  if [ ! -s "$SECRETS" ] || ! $RESUME || $NEW_RUN; then
    log "Scanning local JS files for secrets and links (Global Run $RUN_ID)"
    
    > "$SECRETS" 
    > "$SECRETS_TRUFFLE"
    > "$SECRETS_SECRETFINDER"
    > "$URLS_LINKFINDER"

  if [ -d "$JS_CONTENT_BEAUTIFIED" ]; then
    
    ANALYSIS_DIR="$JS_CONTENT_BEAUTIFIED"
    
    # 1. GF Patterns (FIXED: Safe, Parallel, Localized)
    if has gf; then
      log "Running GF patterns (ip, js-sinks, api-keys, etc.) on beautified JS files..."
      
      for p in ip js-sinks api-keys aws-keys s3-buckets; do
        (
          shopt -s nullglob
          set -- "$ANALYSIS_DIR"/*.js
          if [ "$#" -gt 0 ]; then
            cat "$@" | gf "$p" | sort -u > "$SECRETS_GF/$p.txt" || true
          fi
          shopt -u nullglob
        ) &
      done
      wait
    fi
  
      # 2. TruffleHog
      if has trufflehog; then
        log "Running TruffleHog on the JS content directory..."
        safe_run "trufflehog filesystem $ANALYSIS_DIR >> '$SECRETS_TRUFFLE'"
      fi
  
# 3. SecretFinder
      if has secretfinder; then
        log "Running SecretFinder on beautified JS files..."
        for js_file in "$ANALYSIS_DIR"/*.js; do
          [ -f "$js_file" ] || continue
          safe_run "secretfinder -i '$js_file' -o cli | anew '$SECRETS_SECRETFINDER'"
        done
      fi

      # 4. LinkFinder
      if has linkfinder; then
        log "Running LinkFinder on beautified JS files to extract new URLs."
        for js_file in "$ANALYSIS_DIR"/*.js; do
          [ -f "$js_file" ] || continue
          safe_run "linkfinder -i '$js_file' -o cli | anew '$URLS_LINKFINDER'"
        done
      fi
  
      # Combine all secrets into the master SECRETS file (FIXED: Include all GF files)
      cat "$SECRETS_GF/"*.txt "$SECRETS_TRUFFLE" "$SECRETS_SECRETFINDER" 2>/dev/null | sort -u > "$SECRETS"
    else
      log "WARN: No beautified JS files found in $JS_CONTENT_BEAUTIFIED. Skipping analysis."
    fi
  fi
  
  # ----------------- PARAM DISCOVERY -----------------
  if [ ! -s "$PARAMS_FUZZ" ] || ! $RESUME || $NEW_RUN; then
    log "Discovering parameters with advanced tools (Global Run $RUN_ID)"
    > "$PARAMS_FUZZ"
    
    if [ ! -s "$URLS_FILTERED" ]; then
      log "WARN: $URLS_FILTERED is empty. Skipping parameter discovery."
    else
      log "Starting parameter discovery on $(wc -l < "$URLS_FILTERED") filtered URLs..."
      
      # --- 1. ParamSpider
      if has paramspider; then
        log "Running paramspider..."
        safe_run "paramspider -d $TARGET -o $OUTDIR/params/paramspider.txt"
        if has anew; then cat "$OUTDIR/params/paramspider.txt" | anew "$PARAMS_FUZZ" >/dev/null 2>&1 || true; else cat "$OUTDIR/params/paramspider.txt" | sort -u >> "$PARAMS_FUZZ" || true; fi
      fi

      # --- 2. Arjun
      if has arjun; then
        log "Running arjun on the top 200 filtered URLs..."
        safe_run "cat $URLS_FILTERED | head -n 200 | xargs -I {} -P 10 arjun -u {} -t $((THREADS/10)) -oT \"$OUTDIR/params/arjun_results.txt\""
        if has anew; then cat "$OUTDIR/params/arjun_results.txt" 2>/dev/null | anew "$PARAMS_FUZZ" >/dev/null 2>&1 || true; else cat "$OUTDIR/params/arjun_results.txt" 2>/dev/null | sort -u >> "$PARAMS_FUZZ" || true; fi
      fi

      # --- 3. qsreplace
      if has qsreplace; then
        log "Applying qsreplace to generate fuzz-ready URLs..."
        if has anew; then cat "$URLS_FILTERED" | qsreplace 'FUZZ' | sort -u | anew "$PARAMS_FUZZ" >/dev/null 2>&1 || true; else cat "$URLS_FILTERED" | qsreplace 'FUZZ' | sort -u >> "$PARAMS_FUZZ" || true; fi
      fi
      
      # --- 4. Applying Filters
      log "Applying exclude/whitelist filters to final parameter list."
      apply_exclude "$PARAMS_FUZZ" "$EXCLUDE_ARG"
      apply_whitelist "$PARAMS_FUZZ" "$WHITELIST_ARG"
      
    fi
  fi
  
  # ----------------- GF PATTERN EXTRACTION (URLS) -----------------
  if has gf && [ -s "$URLS_FILTERED" ]; then
    mkdir -p "$OUTDIR/urls/gf"
    for p in xss lfi ssti rce sqli ssrf idor redirect takeover; do
      safe_run "cat $URLS_FILTERED | gf $p | sort -u > $OUTDIR/urls/gf/$p.txt" || true
    done
  fi

  # ----------------- VULNERABILITY SCANNING -----------------
  if ! $SKIP_VULN_SCAN && has nuclei && [ -s "$ALIVE" ]; then
    if [ ! -s "$VULNS_NUCLEI" ] || ! $RESUME || $NEW_RUN; then
      log "Scanning for vulnerabilities with nuclei (extended templates) (Global Run $RUN_ID)"
      safe_run "nuclei -l $ALIVE -t exposures/ -t misconfiguration/ -concurrency $THREADS -o $VULNS_NUCLEI"
    fi
  fi

  # ----------------- DIRECTORY FUZZING -----------------
  if ! $SKIP_DIR_FUZZ && has ffuf && [ -s "$ALIVE" ] && [ -f "$WORDLIST" ]; then
    if [ ! -s "$DIRS_FOUND" ] || ! $RESUME || $NEW_RUN; then
      log "Fuzzing directories with ffuf (Global Run $RUN_ID)"
      # Use full ALIVE list to avoid missing subdomains
      cat "$ALIVE" | xargs -I {} -P 10 ffuf -u {}/FUZZ -w "$WORDLIST" -t $((THREADS/10)) -o "$OUTDIR/directories/ffuf_results.json" -of json || true
      cat "$OUTDIR/directories/ffuf_results.json" 2>/dev/null | jq -r '.results[].url' | sort -u > "$DIRS_FOUND" || true
      # Clean up the large JSON file
      rm -f "$OUTDIR/directories/ffuf_results.json" 2>/dev/null || true
    fi
  fi

  # ----------------- CLOUD ENUM -----------------
  if has cloud_enum; then
    safe_run "cloud_enum -k $TARGET -t $THREADS -l $OUTDIR/osint/cloud_enum.txt"
  fi

  # ----------------- SCREENSHOTS -----------------
  if ! $SKIP_SCREENSHOTS && has gowitness && [ -s "$ALIVE" ]; then
    if [ ! -s "$OUTDIR/screenshots/.done" ] || ! $RESUME || $NEW_RUN; then
      log "Taking screenshots with gowitness (Global Run $RUN_ID)"
      awk '{print $1}' "$ALIVE" | sort -u > "$OUTDIR/alive/for_screenshot.txt"
      safe_run "gowitness scan file -f $OUTDIR/alive/for_screenshot.txt -s $OUTDIR/screenshots --timeout=60 --write-jsonl -D"
      touch "$OUTDIR/screenshots/.done"
    fi
  fi

  # ----------------- SUMMARY -----------------
  find "$OUTDIR" -type f -size 0 -print -delete 2>/dev/null || true
  subs_count=$(wc -l < "$SUBS_ALL" 2>/dev/null || echo 0)
  resolved_count=$(wc -l < "$RESOLVED" 2>/dev/null || echo 0)
  alive_count=$(wc -l < "$ALIVE" 2>/dev/null || echo 0)
  ports_count=$(wc -l < "$PORTS_OPEN" 2>/dev/null || echo 0)
  urls_count=$(wc -l < "$URLS_ALL" 2>/dev/null || echo 0)
  params_count=$(wc -l < "$PARAMS_FUZZ" 2>/dev/null || echo 0)
  vulns_count=$(wc -l < "$VULNS_NUCLEI" 2>/dev/null || echo 0)
  secrets_count=$(wc -l < "$SECRETS" 2>/dev/null || echo 0)
  emails_count=$(wc -l < "$OSINT_EMAILS" 2>/dev/null || echo 0)
  dirs_count=$(wc -l < "$DIRS_FOUND" 2>/dev/null || echo 0)
  
  # Update run info with final stats
  cat >> "$RUN_INFO" << EOF

=== FINAL STATS (Global Run $RUN_ID) ===
Subdomains: $subs_count
Resolved: $resolved_count
Alive: $alive_count
Open Ports: $ports_count
URLs: $urls_count
Fuzz Params: $params_count
Vulns: $vulns_count
Secrets: $secrets_count
Emails: $emails_count
Directories: $dirs_count
Finished: $(date -u +'%Y-%m-%dT%H:%M:%SZ')
EOF

  echo "global_run_id: $RUN_ID" >> "$NOTES"
  echo "subdomains_count: $subs_count" >> "$NOTES"
  echo "resolved_count: $resolved_count" >> "$NOTES"
  echo "alive_count: $alive_count" >> "$NOTES"
  echo "open_ports_count: $ports_count" >> "$NOTES"
  echo "urls_count: $urls_count" >> "$NOTES"
  echo "params_fuzz_count: $params_count" >> "$NOTES"
  echo "vulns_count: $vulns_count" >> "$NOTES"
  echo "secrets_count: $secrets_count" >> "$NOTES"
  echo "emails_count: $emails_count" >> "$NOTES"
  echo "dirs_count: $dirs_count" >> "$NOTES"
  echo "finished: $(date -u +'%Y-%m-%dT%H:%M:%SZ')" >> "$NOTES"
  
  log "Finished ultimate recon for $TARGET (Global Run $RUN_ID): subdomains=$subs_count, resolved=$resolved_count, alive=$alive_count, ports=$ports_count, urls=$urls_count, params=$params_count, vulns=$vulns_count, secrets=$secrets_count, emails=$emails_count, dirs=$dirs_count"
  log "Results saved in: $OUTDIR"

done

log "All targets processed."
