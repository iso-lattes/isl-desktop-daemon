use std::{collections::HashMap, io::Write};

use flags2env::BundledFlags2Env;
use tempfile::NamedTempFile;

pub type EnvMap = HashMap<String, String>;

const CONTRACT: &str = include_str!("../.cli-flags.toml");
const DISABLED_ARBITRARY_COMMAND_ENV: &str = "SCINTILLA_ALLOW_ARBITRARY_CLIENT_COMMANDS";

pub fn apply_cli_flags() -> Result<EnvMap, String> {
    let argv = std::env::args().collect::<Vec<_>>();
    let initial = std::env::vars().collect::<EnvMap>();

    let mut contract = NamedTempFile::new()
        .map_err(|error| format!("cannot create embedded flags-2-env contract: {error}"))?;
    contract
        .write_all(CONTRACT.as_bytes())
        .map_err(|error| format!("cannot materialize embedded flags-2-env contract: {error}"))?;
    let path = contract
        .path()
        .to_str()
        .ok_or_else(|| "flags-2-env contract path is not valid UTF-8".to_owned())?;

    let parser = BundledFlags2Env::new();
    parser
        .audit_config(Some(path))
        .map_err(|error| format!("flags-2-env configuration audit failed: {error}"))?;
    let parsed = parser
        .parse_structured(&argv, Some(path))
        .map_err(|error| format!("flags-2-env parse failed: {error}"))?;

    if !parsed.unknown_options.is_empty() {
        let names = parsed
            .unknown_options
            .iter()
            .map(|option| option.split('=').next().unwrap_or_default())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!("unknown command-line option(s): {names}"));
    }
    if !parsed.errors.is_empty() {
        return Err(format!(
            "invalid command-line value(s): {}",
            parsed.errors.join("; ")
        ));
    }
    if !parsed.extras.is_empty() {
        return Err(format!(
            "unexpected positional argument(s): {}",
            parsed.extras.len()
        ));
    }

    // Fleet precedence is schema defaults < process environment < explicit argv.
    // `parsed.flags` contains TOML defaults and would incorrectly overwrite the
    // real environment. Only explicit argv-derived values are layered here.
    let mut env = initial;
    env.extend(parsed.provided_flags);
    return Ok(sanitize_env(env));
}

fn sanitize_env(mut env: EnvMap) -> EnvMap {
    // Generic authenticated process launch is not part of the desktop daemon
    // client contract. Drop the legacy environment escape hatch even when a
    // parent shell still exports it, so `/v1/processes/start` remains fail-closed.
    env.remove(DISABLED_ARBITRARY_COMMAND_ENV);
    return env;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_arbitrary_process_escape_hatch_is_not_declared() {
        assert!(!CONTRACT.contains("allow-arbitrary-client-commands"));
        assert!(!CONTRACT.contains(DISABLED_ARBITRARY_COMMAND_ENV));
    }

    #[test]
    fn legacy_arbitrary_process_environment_is_removed() {
        let env = EnvMap::from([
            (DISABLED_ARBITRARY_COMMAND_ENV.to_owned(), "true".to_owned()),
            ("RUST_LOG".to_owned(), "info".to_owned()),
        ]);
        let env = sanitize_env(env);

        assert!(!env.contains_key(DISABLED_ARBITRARY_COMMAND_ENV));
        assert_eq!(env.get("RUST_LOG").map(String::as_str), Some("info"));
    }
}
