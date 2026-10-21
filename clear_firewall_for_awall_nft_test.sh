#!/bin/sh
#
# clear_firewall_for_awall_nft_test.sh
#
# Experimental helper for local testing.
#
# This script clears legacy iptables/ip6tables rules safely by setting filter
# policies to ACCEPT first, then flushing rules and deleting user-defined chains.
# It also flushes the nftables ruleset.
#
# Use only on a machine where temporarily opening the firewall is acceptable.

set -u

log() {
    printf '%s\n' "$*"
}

run() {
    log "+ $*"
    "$@"
}

run_ignore() {
    log "+ $*"
    "$@" 2>/dev/null || true
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "error: this script must be run as root"
        exit 1
    fi
}

set_accept_policies() {
    log "== Set legacy filter policies to ACCEPT =="

    run_ignore iptables -P INPUT ACCEPT
    run_ignore iptables -P FORWARD ACCEPT
    run_ignore iptables -P OUTPUT ACCEPT

    run_ignore ip6tables -P INPUT ACCEPT
    run_ignore ip6tables -P FORWARD ACCEPT
    run_ignore ip6tables -P OUTPUT ACCEPT
}

flush_table() {
    cmd="$1"
    table="$2"

    run_ignore "$cmd" -t "$table" -F
    run_ignore "$cmd" -t "$table" -X
    run_ignore "$cmd" -t "$table" -Z
}

clear_legacy_iptables() {
    log "== Clear legacy IPv4 iptables =="

    flush_table iptables filter
    flush_table iptables nat
    flush_table iptables mangle
    flush_table iptables raw
    flush_table iptables security

    log "== Clear legacy IPv6 ip6tables =="

    flush_table ip6tables filter
    flush_table ip6tables nat
    flush_table ip6tables mangle
    flush_table ip6tables raw
    flush_table ip6tables security
}

clear_nftables() {
    log "== Flush nftables ruleset =="

    run_ignore nft flush ruleset
}

show_status() {
    log "== iptables-save =="
    run_ignore iptables-save

    log "== ip6tables-save =="
    run_ignore ip6tables-save

    log "== nft list ruleset =="
    run_ignore nft list ruleset
}

main() {
    require_root

    log "WARNING: this will temporarily open the legacy iptables/ip6tables firewall."
    log "Press Ctrl-C within 5 seconds to abort."
    sleep 5

    set_accept_policies
    clear_legacy_iptables
    clear_nftables
    show_status

    log "done"
}

main "$@"
