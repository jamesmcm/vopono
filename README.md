# vopono

vopono is a tool to run applications through VPN tunnels via temporary
network namespaces. This allows you to run only a handful of
applications through different VPNs whilst keeping your main connection
as normal.

This is pre-alpha software, currently only PrivateInternetAccess is
supported, using OpenVPN and iptables. Support for nftables, the
WireGuard protocol and more VPN providers (Mullvad, etc.) will be added
soon.

## Etymology

vopono is the pronunciation of the letters VPN in Esperanto.

Se vi ankaŭ parolas Esperanton, bonvolu serĉi min en la kanalo de
Discord de Rust Programming Language Community.

## Usage

```
$ vopono exec --provider privateinternetaccess --server pl "curl ifconfig.co/country"
Poland
```

You can also launch graphical applications like `firefox`,
`transmission-gtk`, etc. - the network namespace will be cleaned up when
the application is terminated. Note you may need to run them as your own
user:

```
$ vopono exec --provider privateinternetaccess --server mexico "sudo -u
$USER firefox"
Poland
```

Place your username and password in
`~/.config/vopono/pia/openvpn/auth.txt` - the username on the first
line, and the password on the second (with a newline). Otherwise you
will be prompted for your credentials.

### Known issues

* OpenVPN output is not muted - you will see the output from OpenVPN
  when you run your application, this a pain for command-line
  applications but since it is difficult to handle failures in OpenVPN
  overall I felt it was left to leave this enabled for now (for
  debugging).
* Multiple network namespaces at once are not currently supported. This
  is due to the allocation of static IP addresses and will be resolved
  soon. It is also planned to add an option to list currently running
  vopono network namespaces.
* Multiple applications cannot currently share the same network
  namespace. This requires keeping the network namespace alive between
  different instances of vopono. This will be resolved soon, probably
  with lockfiles preventing premature clean-up. It is also planned to
  list currently running applications in vopono and their network namespaces.
* Only PrivateInternetAccess is supported - will add support for other
  providers soon.
* Only OpenVPN is supported - will add support for WireGuard soon.
* iptables is required - will add support for nftables (and possibly
  ufw) soon.
* sudo is required - it is planned to remove all direct commands from
  vopono and instead request privilege escalation inside vopono directly.
* Credentials are always stored in plaintext in configuration - will add
  option to not store credentials soon, but it seems OpenVPN needs them
  provided in plaintext.
* Applications launch as root by default (including OpenVPN) - will be
  addressed shortly to make current user the default.
* Custom VPN servers are not supported - support for custom VPN
  connections via provided .ovpn files is planned.
* Cannot set default VPN provider and server - will be added shortly.
* Configuration of VPN connection is limited - support will be added for
  different keylengths, etc. in the future.



## Installation

### From this repository (with Cargo)

Run the install script provided: `install.sh` - this will `cargo
install` the repository and copy over the configuration files to
`~/.config/vopono/`

## License

vopono is licensed under the GPL Version 3.0 (or above), see the LICENSE
file or https://www.gnu.org/licenses/gpl-3.0.en.html

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, will be licensed under the GPLv3 (or
above), without any additional terms or conditions.
