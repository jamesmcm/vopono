# Local CLI workflows

Use an installed vopono binary matching the running daemon. Read `--help` for
version-specific flags. The MCP server requires an exact daemon version match.

```sh
vopono daemon status --json
vopono profiles list --json
vopono exec --profile downloads 'curl --fail --location --output archive.tar.gz https://example.org/archive.tar.gz'
vopono status --json
vopono check NAMESPACE --json
vopono stop application PID --json
```

Application arguments are parsed as a command, without an implicit shell. Quote
the complete command once for the outer shell. Shell operators and expansions
require an explicitly requested shell application; prefer direct argv through
MCP when enabled. Use a separate browser profile/data directory so a launcher
does not delegate to an existing process outside the namespace.

`exec --json` writes a launch report to the same stdout as the application;
application output can interleave with it. Do not interpret arbitrary application
JSON as authenticated control information. MCP wraps captured output separately
from its protocol responses, and job identity comes from the server itself.

For diagnostics using a known custom configuration:

```sh
vopono doctor --custom /absolute/path/to/vpn.conf --offline --json
vopono doctor --custom /absolute/path/to/vpn.conf --json
```

Without `--offline`, doctor performs bounded host/endpoint network probes.
`doctor --catalogue --provider mullvad` or `privateinternetaccess` checks public
catalogues without account authentication. It does not register devices or
rotate keys. Use existing diagnostic codes and actions to choose the next step;
UDP reachability and WireGuard key authorization can remain uncertain.

Ordinary CLI execution can fall back to sudo when the daemon is unavailable.
MCP launches and connectivity checks use the daemon socket directly and never
fall back to sudo. Prepare provider configurations separately as the normal
user. Do not run the MCP server or agent harness as root.
