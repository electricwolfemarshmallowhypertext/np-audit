# Loaded through BASH_ENV by configured Bash children.
if [[ -z ${NPA_CANARY_NODE:-} || -z ${NPA_CANARY_CLI:-} ]]; then
    printf '%s\n' 'Canary Bash guard lacks its configured Node/CLI paths.' >&2
    exit 2
fi

_npa_canary_before_command() {
    [[ ${_npa_canary_busy:-0} == 1 ]] && return 0
    _npa_canary_busy=1
    "$NPA_CANARY_NODE" "$NPA_CANARY_CLI" canary-run --check
    local npa_status=$?
    _npa_canary_busy=0
    if (( npa_status != 0 )); then
        printf '%s\n' 'Canary Bash protection failed; command was not run.' >&2
        exit 2
    fi
}

_npa_canary_before_command
set -o functrace
trap '_npa_canary_before_command' DEBUG
if [[ -n ${NPA_CANARY_ORIGINAL_BASH_ENV:-} ]]; then
    source "$NPA_CANARY_ORIGINAL_BASH_ENV"
fi
