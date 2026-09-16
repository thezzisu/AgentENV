# Runs as root in the guest's initial PID namespace, including container PIDs.
# Use the tools-drive busybox; base images need no extra packages.
set -eu
bb=/agentenv/bin/busybox
test -d /proc/1/fd || { echo 'guest procfs is unavailable' >&2; exit 1; }

kvm_owners() {
    for proc in /proc/[0-9]*; do
        for fd in "$proc"/fd/*; do
            target=$($bb readlink "$fd" 2>/dev/null) || continue
            case "$target" in
                /dev/kvm|anon_inode:kvm-vm|anon_inode:kvm-vcpu*)
                    echo "${proc##*/}"
                    break
                    ;;
            esac
        done
    done
}

owners=$(kvm_owners)
test -n "$owners" || exit 0
initial_owners=$owners
# Ask the existing service/container manager to stop its workload so restart
# policies do not race capture. Never stop a shared service such as envd merely
# because a nested VMM is one of its descendants.
for pid in $owners; do
    test -r "/proc/$pid/cgroup" || continue
    while IFS=: read -r hierarchy controllers cgroup; do
        unit=${cgroup##*/}
        case "$unit" in
            docker-*.scope)
                if command -v docker >/dev/null 2>&1; then
                    container=${unit#docker-}
                    docker stop --time 5 "${container%.scope}" >/dev/null
                fi
                ;;
            *.service)
                if command -v systemctl >/dev/null 2>&1 &&
                    test "$(systemctl show --property=MainPID --value "$unit")" = "$pid"; then
                    systemctl stop --no-block "$unit"
                fi
                ;;
        esac
    done < "/proc/$pid/cgroup"
done
owners=$(kvm_owners)
for pid in $owners; do
    test "$pid" -gt 1 || { echo 'refusing to signal guest init' >&2; exit 1; }
    kill -TERM "$pid" 2>/dev/null || true
done

# A signal alone is insufficient: KVM file descriptors must be closed. Allow
# SIGTERM cleanup, escalate for unresponsive VMMs, and reject service respawns.
round=0
idle=0
while test "$round" -lt 100; do
    remaining=$(kvm_owners)
    if test -z "$remaining"; then
        idle=$((idle + 1))
        if test "$idle" -ge 2; then
            $bb sync
            echo "$initial_owners"
            exit 0
        fi
    else
        idle=0
        for pid in $remaining; do
            case " $(echo "$owners" | $bb tr '\n' ' ') " in
                *" $pid "*) ;;
                *) echo 'nested KVM restarted; stop its service before capture' >&2; exit 1 ;;
            esac
            if test "$round" -ge 50; then
                kill -KILL "$pid" 2>/dev/null || true
            fi
        done
    fi
    round=$((round + 1))
    $bb sleep 0.1
done
echo 'nested KVM resources remain; refusing capture' >&2
exit 1
