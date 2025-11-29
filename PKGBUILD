    # Maintainer: Your Name <your_email@example.com>
    pkgname=voponotest
    pkgver=0.10.15
    pkgrel=1
    pkgdesc='Run applications through VPN connections in network namespaces'
    arch=('any')
    url="https://github.com/Schwarzen/voponotest"
    license=('GPL3')
makedepends=('git' 'rust')
optdepends=('openvpn: for OpenVPN connections' 'wireguard-tools: for Wireguard connections' 'shadowsocks-libev: for Shadowsocks support (Mullvad)' 'openfortivpn: for FortiClient VPN connections' 'libnatpmp: for ProtonVPN port forwarding support' 'trojan: for Trojan Wireguard forwarding support')
source=("git+${url}.git")

provides=('voponotest')
conflicts=('voponotest')
    sha256sums=('SKIP')

    pkgver() {
      cd "${srcdir}/${pkgname%-git}"
      git describe --long --tags | sed 's/\([^-]*-\)g/\1r/;s/\([^-]*\)-\([^-]*\)/\1.\2/'
    }

 build() {
  cd "$pkgname-$pkgver"
  
  CFLAGS+=" -ffat-lto-objects" cargo build --release
}

package() {
  cd "$pkgname-$pkgver"

  install -Dm755 target/release/${pkgname} "${pkgdir}/usr/bin/${pkgname}"
  install -Dm644 LICENSE "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}
