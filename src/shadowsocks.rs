// TODO:
// Check if OpenVPN config uses shadowsocks:
// socks-proxy 127.0.0.1 1080
// return port to listen on
// In namespace run:
// ss-local -s 69.4.234.146 -p 443 -l 1080 -k 23#dfsbbb -m chacha20
// -l port should come from config
// -p port should come from remote config
// -s should be random route IP from config
// -k and -m can be fixed for now (Mullvad)
