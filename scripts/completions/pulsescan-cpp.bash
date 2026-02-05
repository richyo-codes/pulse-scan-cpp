#!/usr/bin/env bash

_pulsescan_cpp_completions() {
  local cur prev
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"

  case "${prev}" in
    -m|--mode)
      COMPREPLY=( $(compgen -W "connect banner udp" -- "${cur}") )
      return 0
      ;;
    --output)
      COMPREPLY=( $(compgen -W "text json" -- "${cur}") )
      return 0
      ;;
  esac

  local opts="
    -p --ports
    -t --timeout
    --max-inflight
    -m --mode
    --banner-timeout
    --banner-bytes
    --ping
    --open
    --debug-dns
    -v --verbose
    -4 -6
    --icmp-ping
    -c --icmp-count
    --reverse-dns
    --sandbox
    --no-sandbox
    --interval
    --top-ports
    --output
    -h --help
  "

  if [[ "${cur}" == -* ]]; then
    COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
  fi
}

complete -F _pulsescan_cpp_completions pulsescan-cpp
