use std::{collections::HashMap, io::Write};

use flags2env::BundledFlags2Env;
use tempfile::NamedTempFile;

pub type EnvMap = HashMap<String, String>;

const CONTRACT: &str = include_str!("../.cli-flags.toml");

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
    return Ok(env);
}
