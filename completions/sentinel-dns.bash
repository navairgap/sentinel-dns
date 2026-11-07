# Bash completion for sentinel-dns.
_sentinel_dns() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local prev="${COMP_WORDS[COMP_CWORD-1]}"
    local commands="analyze watch selftest config help"
    local flags="-c --config -v --verbose -V --version -h --help"

    case "$prev" in
        -c|--config)
            # Complete config file names.
            compgen -f -X '!*.json' -- "$cur" | sed 's/ /\\ /g'
            return 0
            ;;
        analyze)
            # Complete pcap file names.
            compgen -f -X '!*.pcap' -- "$cur" | sed 's/ /\\ /g'
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "$flags" -- "$cur"))
        return 0
    fi

    if [[ "$prev" == "sentinel-dns" ]]; then
        COMPREPLY=($(compgen -W "$commands" -- "$cur"))
        return 0
    fi

    # After a command word, offer flags and (for analyze) more files.
    if [[ "${COMP_WORDS[1]}" == "analyze" ]]; then
        COMPREPLY=($(compgen -f -X '!*.pcap' -- "$cur" | sed 's/ /\\ /g') $(compgen -W "$flags" -- "$cur"))
    else
        COMPREPLY=($(compgen -W "$flags" -- "$cur"))
    fi
    return 0
}
complete -F _sentinel_dns sentinel-dns
