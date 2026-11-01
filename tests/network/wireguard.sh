#!/usr/bin/env bash
# Run only in a disposable mount/network/PID namespace; no commercial account or internet.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
if [[ ${1:-} != --isolated ]]; then
    echo 'Run: sudo unshare --mount --net --pid --fork --mount-proc tests/network/wireguard.sh --isolated /absolute/path/to/vopono'
    exit 2
fi
[[ $EUID == 0 ]] || { echo 'Root is required inside the disposable namespaces'; exit 2; }
[[ $$ == 1 ]] || { echo "Refusing to run outside a fresh PID namespace"; exit 2; }
binary=$(realpath "${2:?Pass the built vopono binary}")
test_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
for dependency in ip wg nft openvpn openssl natpmpc python3 runuser; do command -v "$dependency" >/dev/null; done
mount --make-rprivate /
scratch=$(mktemp -d /tmp/vopono-network.XXXXXX)
chmod 755 "$scratch"
cleanup() {
    local code=$?
    if (( code != 0 )); then
        echo 'Synthetic VPN test failed. Last daemon messages:'
        tail -50 "$scratch/daemon.log" 2>/dev/null || true
        tail -20 "$scratch/client1.log" 2>/dev/null || true
    fi
    # PID namespace exit kills every remaining daemon, service and application.
    rm -rf "$scratch"
}
trap cleanup EXIT
# Isolate all fixed privileged paths, including DNS overlays and the daemon socket.
mkdir "$scratch/etc"
cp -a /etc/. "$scratch/etc/"
mount --bind "$scratch/etc" /etc
mount -t tmpfs tmpfs /run
mkdir -p /run/netns
user=$(getent passwd 1000 | cut -d: -f1)
[[ -n $user ]] || user=nobody
uid=$(id -u "$user")
gid=$(id -g "$user")
mkdir -p "$scratch/config/vopono"
chown -R "$uid:$gid" "$scratch/config"
chmod 700 "$scratch/config"
client() { runuser -u "$user" -- env XDG_CONFIG_HOME="$scratch/config" "$binary" "$@" < /dev/null; }
wait_for() {
    for _ in $(seq 1 100); do if "$@" 2>/dev/null; then return 0; fi; sleep 0.2; done
    return 1
}
ip link set lo up
ip netns add peer
ip link add uplink type veth peer name peerlink
ip link set peerlink netns peer
ip addr add 192.0.2.1/24 dev uplink
ip link set uplink up
ip route add default via 192.0.2.2 dev uplink
ip -n peer addr add 192.0.2.2/24 dev peerlink
ip -n peer link set peerlink up
ip -n peer link set lo up
umask 077
wg genkey > "$scratch/server.key"
wg genkey > "$scratch/client.key"
server_public=$(wg pubkey < "$scratch/server.key")
client_public=$(wg pubkey < "$scratch/client.key")
ip -n peer link add wgpeer type wireguard
ip netns exec peer wg set wgpeer private-key "$scratch/server.key" listen-port 51820 peer "$client_public" allowed-ips 10.66.0.2/32,fd66::2/128
ip -n peer addr add 10.66.0.1/24 dev wgpeer
ip -n peer addr add fd66::1/64 dev wgpeer
ip -n peer addr add 1.1.1.1/32 dev wgpeer
ip -n peer addr add 2606:4700:4700::1111/128 dev wgpeer
ip -n peer link set wgpeer up
ip netns exec peer python3 "$test_dir/peer.py" > "$scratch/peer.log" 2>&1 &
cat > "$scratch/client.conf" <<CONFIG
[Interface]
PrivateKey = $(cat "$scratch/client.key")
Address = 10.66.0.2/32, fd66::2/128
DNS = 10.66.0.1
[Peer]
PublicKey = $server_public
Endpoint = 192.0.2.2:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 1
CONFIG
chown "$uid:$gid" "$scratch/client.conf"
RUST_LOG=debug "$binary" daemon > "$scratch/daemon.log" 2>&1 &
wait_for test -S /run/vopono.sock
name="test_wg-u$uid"
client exec --custom "$scratch/client.conf" --protocol wireguard --custom-netns-name test_wg --interface uplink --firewall nftables --monitor --recover 'sleep 180' > "$scratch/client1.log" 2>&1 &
wait_for test -e "/run/netns/$name"
probe() { client check "$name" --json > "$scratch/check.json" 2>/dev/null && python3 -c 'import json,sys; r=json.load(open(sys.argv[1]))["result"]; assert r["connected"] and r["dns"]["resolved_ips"]' "$scratch/check.json"; }
# Both inner IP families and DNS must work; the host underlay is forbidden.
dual_stack_ready() { probe && python3 -c 'import json,sys; r=json.load(open(sys.argv[1]))["result"]; assert "latency_ms" in r["ipv4"] and "latency_ms" in r["ipv6"]' "$scratch/check.json"; }
wait_for dual_stack_ready
blocked() { ip netns exec "$name" python3 -c 'import socket; s=socket.socket(); s.settimeout(1)
try: s.connect(("192.0.2.2",443))
except OSError: raise SystemExit(0)
raise SystemExit("Kill switch bypassed")'; }
blocked
client exec --existing-netns "$name" --interface uplink 'sleep 180' > "$scratch/client2.log" 2>&1 &
wait_for bash -c 'ip netns pids "$1" | xargs -r ps -o comm= -p | awk '\''$1 == "sleep" {n++} END {exit n < 2}'\''' _ "$name"
# Status must show both independent clients, including the attached session.
two_visible() { client status --json | python3 -c 'import json,sys; assert len(json.load(sys.stdin)["namespaces"][0]["applications"]) == 2'; }
wait_for two_visible
# Terminating the creator must preserve the second app's tunnel and namespace.
creator=$(client status --json | python3 -c 'import json,sys; print(min(a["pid"] for a in json.load(sys.stdin)["namespaces"][0]["applications"]))')
client stop application "$creator" --json > /dev/null
probe
blocked
# Verify opt-in telemetry is available through the existing status API.
health_connected() { client status --json | python3 -c 'import json,sys; h=json.load(sys.stdin)["namespaces"][0]["health"]; assert h and h["state"] == "connected"'; }
wait_for health_connected
# Simulate a transport interruption, verify fail-closed behavior and recovery.
ip -n peer link set wgpeer down
if probe 2>/dev/null; then echo 'Connectivity unexpectedly survived peer outage'; exit 1; fi
blocked
# Wait for repeated failures to trigger the bounded keepalive recovery action.
recovery_observed() { client status --json | python3 -c 'import json,sys; h=json.load(sys.stdin)["namespaces"][0]["health"]; assert h and h["reconnect_attempts"] >= 1'; }
for _ in $(seq 1 50); do if recovery_observed 2>/dev/null; then break; fi; sleep 1; done
recovery_observed
blocked
ip -n peer link set wgpeer up
wait_for probe
blocked
# Explicit stop must be authoritative and idempotent at the resource level.
client stop namespace "$name" --json > /dev/null
[[ ! -e /run/netns/$name ]]
# Reusing the name immediately must survive the previous controller's completion.
client exec --custom "$scratch/client.conf" --protocol wireguard --custom-netns-name test_wg --interface uplink --firewall nftables --create-netns-only '' > "$scratch/create.log" 2>&1
probe
client stop namespace "$name" --json > /dev/null
[[ ! -e /run/netns/$name ]]
# Root-owned input and unsafe OpenVPN options must be rejected before spawning OpenVPN.
printf 'root-only-credential\n' > "$scratch/root-only"
chmod 600 "$scratch/root-only"
cat > "$scratch/unsafe.ovpn" <<CONFIG
client
dev tun
proto udp
remote 192.0.2.2 1194
plugin /tmp/unsupported.so
CONFIG
chown "$uid:$gid" "$scratch/unsafe.ovpn"
if client exec --custom "$scratch/unsafe.ovpn" --protocol openvpn --interface uplink --firewall nftables --json true > "$scratch/rejected.json" 2>/dev/null; then
    echo 'Unsafe OpenVPN configuration unexpectedly accepted'; exit 1
fi
python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["error"]["diagnostics"][0]; assert d["state"] in ("warning", "fail")' "$scratch/rejected.json"
if client __read-user-file "$scratch/root-only" >/dev/null 2>&1; then
    echo 'Unprivileged config reader accessed a root-only input'; exit 1
fi
python3 "$test_dir/regressions.py" "$binary" "$scratch" "$user"
python3 "$test_dir/lifecycle.py" "$binary" "$scratch" "$user"
python3 "$test_dir/capacity.py" "$binary" "$scratch" "$user"
python3 "$test_dir/forwarding.py" "$binary" "$scratch" "$user"
python3 "$test_dir/openvpn.py" "$binary" "$scratch" "$user"
python3 "$test_dir/mcp.py" "$binary" "$scratch" "$user"
python3 "$test_dir/recovery.py" "$binary" "$scratch" "$user"
# Failed setup must release its veth, namespace and ownership record as well.
[[ $(ip netns list | wc -l) == 1 ]]
[[ $(ip -j link | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))') == 2 ]]
echo 'PASS: WireGuard handshake, dual-stack TCP, DNS, shared lifetime, isolation, outage recovery, stop and name reuse'
