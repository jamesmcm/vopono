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

To add support for a new VPN provider, the main task is to add functions
to generate their OpenVPN and/or Wireguard config files in
`src/sync.rs`.

Then add the provider name to the VpnProvider enum, and add logic to the
implementations in `src/vpn.rs` for the new provider.

For Wireguard we parse wg-quick config files. 

For OpenVPN we create: 
* A serverlist CSV with host, port and protocol
* The general OpenVPN config file (for use across all of that provider's
servers - remove any references to `remote` or `proto` in this file)
* The CA cert of the VPN provider
* If used, the Certificate Revocation List (CRL) for the provider too.

Use the `include_str` macro to include any files that cannot be
downloaded (i.e. if they are behind a captcha). Only do this when
absolutely necessary as it will increase the binary size.

Note that since Mullvad is the only Wireguard provider at the moment,
adding a new Wireguard provider may require more changes (i.e. if the
MTU differs, etc.)

In the future, this may be modified to use a struct per VpnProvider with
traits for OpenVPN and Wireguard support respectively, to encapsulate
the logic for each provider separately and make it easier to add new
providers from examples.

## Other code contributions

Please check the Github issues for larger planned changes, or grep the
codebase for `TODO` :) 

## Licensing

vopono is licensed under the GPL Version 3.0 (or above), see the LICENSE
file or https://www.gnu.org/licenses/gpl-3.0.en.html

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, will be licensed under the GPLv3 (or
above), without any additional terms or conditions.
