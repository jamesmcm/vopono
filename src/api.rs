use serde::Serialize;

/// Version of the machine-readable JSON interface shared by all frontend
/// commands. Bump on any breaking change to a serialized document shape.
pub const SCHEMA_VERSION: u8 = 1;

/// Pretty-print a JSON document to stdout.
///
/// Single place for the `serde_json::to_string_pretty` + `println` pattern so
/// every command emits identically formatted output.
pub fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Emit the success acknowledgement used by commands that perform an action
/// (e.g. sync) without producing a richer result document.
pub fn print_success_json() {
    println!(
        "{}",
        serde_json::json!({"version": SCHEMA_VERSION, "success": true})
    );
}
