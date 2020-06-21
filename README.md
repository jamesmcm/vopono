# vopono

vopono is a tool to run applications through VPN tunnels via temporary
network namespaces. This allows you to run only a handful of
applications through different VPNs simultaneously, whilst keeping your main connection
as normal.

This is alpha software, currently only Mullvad, TigerVPN and
PrivateInternetAccess are supported.

At the moment, both iptables and nftables are required.

## Screenshot

Screenshot showing an example with firefox, google-chrome-stable and
lynx all running through different VPN connections:

![Screenshot](screenshot.png)

## Supported Providers

| Provider              | OpenVPN support | Wireguard support | 
|-----------------------|-----------------|-------------------|
| Mullvad               | ✅              | ✅                |
| PrivateInternetAccess | ✅              | ❌                |
| TigerVPN              | ✅              | ❌                |

## Usage

Applications will be run as the current user by default (you can use
`sudo -u USERNAME program` as the command to run as another user).

vopono will call sudo if required, it is recommended to run as the
current user and let vopono call sudo so that the configuration
directories are correctly inferred and the final command is not run as
root.

### Wireguard

For Mullvad, download the [Wireguard connection configuration files](https://mullvad.net/en/account/#/wireguard-config/) (the
wg-quick ones), and extract them to `~/.config/vopono/mv/wireguard/`.

Install vopono and initialise configuration:

```bash
$ yay -S vopono-git
$ vopono init
```

Copy Wireguard config files:

```bash
$ mkdir -p ~/.config/vopono/mv/wireguard/
$ unzip mullvad_wireguard_linux_all_all.zip -d ~/.config/vopono/mv/wireguard/
```

Run vopono:

```bash
$ vopono exec --provider mullvad --server se --protocol wireguard "transmission-gtk"
```

The server prefix will be searched against available servers and a
random one will be chosen (and reported in the terminal).

### OpenVPN

```bash
$ vopono exec --provider privateinternetaccess --server pl "curl ifconfig.co/country"
Poland
```

You can also launch graphical applications like `firefox`,
`transmission-gtk`, etc. - the network namespace will be cleaned up when
the application is terminated. Note you may need to run them as your own
user:

```bash
$ vopono exec --provider privateinternetaccess --server mexico "firefox"
```

The server prefix will be searched against available servers (both
server names and aliases in the provider's `serverlist.csv`) and a
random one will be chosen (and reported in the terminal).

Place your username and password in
`~/.config/vopono/pia/openvpn/auth.txt` - the username on the first
line, and the password on the second (with a newline). Otherwise you
will be prompted for your credentials.

For PrivateInternetAccess these should be the same as your account
credentials.

For TigerVPN you can view your OpenVPN credentials [online on the "geeks" dashboard](https://www.tigervpn.com/dashboard/geeks).
The OpenVPN credentials are **not** the same as your TigerVPN account credentials.

For Mullvad you can obtain your OpenVPN credentials, by downloading the
[OpenVPN configuration files](https://mullvad.net/en/account/#/openvpn-config/)
and checking `mullvad_userpass.txt`. The OpenVPN credentials are **not**
the same as your Mullvad account credentials.

### Custom Providers

If you use another commercial VPN provider, please open a Pull Request here with
the necessary configuration and serverlist.

For private VPN connections, you can use a custom provider, by passing
the complete configuration file to vopono (i.e. an OpenVPN .ovpn config
file or a Wireguard wg-quick .conf file).

```bash
$ vopono -v exec --custom ~/custom_wireguard.conf --protocol wireguard "firefox"
```

```bash
$ vopono -v exec --custom ./custom_openvpn.ovpn --protocol openvpn "firefox"
```

Note that in the OpenVPN case the command must be executed in the same
directory as any accompanying files (CA certificates, authentication
files, etc.) and the user authentication must be by file (OpenVPN will
fail to request user and password otherwise, due to being launched in
the background).

### Firefox

Note if running multiple Firefox sessions, they need to run separate
profiles in order to force Firefox to run them as separate processes.

### Known issues

* OpenVPN output is not parsed - this means you need to read the output
  to ensure there are not authentication errors, etc.
* OpenVPN output is not muted - you will see the output from OpenVPN
  when you run your application, this a pain for command-line
  applications but since it is difficult to handle failures in OpenVPN
  overall I felt it was left to leave this enabled for now (for
  debugging).
* It is currently not possible to list running vopono network namespaces.
* OpenVPN credentials are always stored in plaintext in configuration - will add
  option to not store credentials soon, but it seems OpenVPN needs them
  provided in plaintext.
* Cannot set default VPN provider and server - will be added shortly.
* Configuration of OpenVPN connection is limited - support will be added for
  different keylengths, etc. in the future.
* Split iptables and nftables dependencies so user can choose one or the
  other.
* Server lists are maintained in the repo and there is no way to update
  them from vopono itself.

## Installation

### AUR (Arch Linux)

Install the `vopono-git` package with your favourite AUR helper.

This will install the default configuration files to `/usr/share/doc/vopono`,
copy them to `~/.config/vopono` manually if you want to configure vopono
prior to your first execution (i.e. to add Wireguard configuration files),
or run `vopono init` to have vopono copy them automatically.

```bash
$ yay -S vopono-git
$ vopono init
```

### From this repository (with Cargo)

Run the install script provided: `install.sh` - this will `cargo
install` the repository and copy over the configuration files to
`~/.config/vopono/`

## License

vopono is licensed under the GPL Version 3.0 (or above), see the LICENSE
file or https://www.gnu.org/licenses/gpl-3.0.en.html

## Etymology

vopono is the pronunciation of the letters VPN in Esperanto.

Se vi ankaŭ parolas Esperanton, bonvolu serĉi min en la kanalo de
Discord de Rust Programming Language Community.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, will be licensed under the GPLv3 (or
above), without any additional terms or conditions.
