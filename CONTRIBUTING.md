# Contributing to vopono

## Building

Clone the repo and build with `cargo build`.

Note the minimum supported Rust version is 1.43.

### Clippy

Please run clippy before submitting a PR:

```bash
$ cargo clean
$ cargo clippy --all-features --all-targets
```

## Adding a new VPN provider

Adding support for a new VPN provider is as simple as adding the
relevant files to `src/providers/` defining Structs which implement the
base `Provider` trait and at least one of the `OpenVpnProvider` or
`WireguardProvider` traits.

See the existing entries in that directory for examples.

The main methods to implement are `create_openvpn_config()` and
`create_wireguard_config()` respectively, which must generate all of the
provider's config files (prompting the user for any options), and write
the credentials to an authentication file for OpenVPN. For OpenVPN these
will be `.ovpn` config files, for Wireguard they will be wg-quick
`.conf` files.

Note the `ConfigurationChoice` trait is provided to make it easier to
provide an enum of choices to the user (i.e. selecting between different
configurations- TCP vs. UDP, etc.).

The new provider must also be added to the `VpnProvider` enum in
`src/providers/mod.rs` to be able to convert from the StructOpt provider
argument to the structs implementing the traits above.

Note that for OpenVPN it is also necessary to create any additional
files that the config files refer to, such as the CA certificate or CRL
file.

Use the `include_str` macro to include any files that cannot be
downloaded (i.e. if they are behind a captcha). Only do this when
absolutely necessary as it will increase the binary size.

Note that since Mullvad is the only Wireguard provider at the moment,
adding a new Wireguard provider may require more changes (i.e. if the
MTU differs, etc.)

## Other code contributions

Please check the Github issues for larger planned changes, or grep the
codebase for `TODO` :) 

## Licensing

vopono is licensed under the GPL Version 3.0 (or above), see the LICENSE
file or https://www.gnu.org/licenses/gpl-3.0.en.html

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, will be licensed under the GPLv3 (or
above), without any additional terms or conditions.
