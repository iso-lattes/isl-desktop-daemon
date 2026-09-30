from pathlib import Path

path = Path("src/main.rs")
text = path.read_text()


def replace_once(old: str, new: str, label: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    text = text.replace(old, new, 1)


replace_once(
    "use serde_json::{Value, json};\nuse std::{\n    collections::HashMap,\n    env,",
    "use serde_json::{Value, json};\nuse sha2::{Digest, Sha256};\nuse std::{\n    collections::HashMap,\n    env,\n    fs,\n    io::Read,",
    "imports",
)
replace_once(
    "struct Cell {\n    child: Child,",
    "struct Cell {\n    artifact_sha256: String,\n    child: Child,",
    "cell digest field",
)
replace_once(
    "struct CellStatus {\n    tenant_id: String,\n    deployment_id: String,\n    invocation_count: u64,",
    "struct CellStatus {\n    tenant_id: String,\n    deployment_id: String,\n    artifact_sha256: String,\n    invocation_count: u64,",
    "status digest field",
)
replace_once(
    "            tenant_id: key.tenant_id,\n            deployment_id: key.deployment_id,\n            invocation_count: cell.invocation_count,",
    "            tenant_id: key.tenant_id,\n            deployment_id: key.deployment_id,\n            artifact_sha256: cell.artifact_sha256.clone(),\n            invocation_count: cell.invocation_count,",
    "status digest value",
)
old_ensure = '''async fn ensure_cell(state: &AppState, key: &CellKey) -> Result<Arc<Mutex<Cell>>> {
    if let Some(cell) = state.cells.lock().await.get(key).cloned() {
        let running = {
            let mut guard = cell.lock().await;
            guard.child.try_wait()?.is_none()
        };
        if running {
            return Ok(cell);
        }
        let _ = retire_cell(state, key).await;
    }

    let worker_script = artifact_path(&state.artifact_root, key, "worker.js")?;
    if !worker_script.is_file() {
        bail!("worker artifact is missing for the requested deployment");
    }

    let live_permit = state.cell_slots.clone().try_acquire_owned().map_err(|_| {
        anyhow!("live V8 cell limit reached; retire an idle cell before cold start")
    })?;

    let mut child = Command::new(state.worker_command.as_ref())
        .env("ISL_TENANT_ID", &key.tenant_id)
        .env("ISL_DEPLOYMENT_ID", &key.deployment_id)
        .env("ISL_WORKER_SCRIPT", &worker_script)
        .env(
            "ISL_MAX_REUSE_INVOCATIONS",
            state.max_cell_invocations.to_string(),
        )
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to start {}", state.worker_command))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("worker stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("worker stdout unavailable"))?;
    let cell = Arc::new(Mutex::new(Cell {
        child,
        stdin,
        stdout: BufReader::new(stdout),
        invocation_count: 0,
        _live_permit: live_permit,
    }));

    let mut cells = state.cells.lock().await;
    if let Some(existing) = cells.get(key).cloned() {
        drop(cells);
        let mut unused = cell.lock().await;
        let _ = unused.child.kill().await;
        let _ = unused.child.wait().await;
        return Ok(existing);
    }
    cells.insert(key.clone(), cell.clone());
    return Ok(cell);
}
'''
new_ensure = '''async fn ensure_cell(state: &AppState, key: &CellKey) -> Result<Arc<Mutex<Cell>>> {
    let worker_script = artifact_path(&state.artifact_root, key, "worker.js")?;
    require_regular_file(&worker_script, "V8 worker artifact")?;
    let artifact_sha256 = sha256_file(&worker_script)?;

    if let Some(cell) = state.cells.lock().await.get(key).cloned() {
        let reusable = {
            let mut guard = cell.lock().await;
            let running = guard.child.try_wait()?.is_none();
            running && guard.artifact_sha256 == artifact_sha256
        };
        if reusable && sha256_file(&worker_script)? == artifact_sha256 {
            return Ok(cell);
        }
        let _ = retire_cell(state, key).await;
    }

    require_regular_file(&worker_script, "V8 worker artifact")?;
    let actual_sha256 = sha256_file(&worker_script)?;
    if actual_sha256 != artifact_sha256 {
        bail!("V8 worker artifact changed while preparing a warm cell");
    }

    let live_permit = state.cell_slots.clone().try_acquire_owned().map_err(|_| {
        anyhow!("live V8 cell limit reached; retire an idle cell before cold start")
    })?;

    let mut child = Command::new(state.worker_command.as_ref())
        .env("ISL_TENANT_ID", &key.tenant_id)
        .env("ISL_DEPLOYMENT_ID", &key.deployment_id)
        .env("ISL_WORKER_SCRIPT", &worker_script)
        .env("ISL_ARTIFACT_SHA256", &artifact_sha256)
        .env(
            "ISL_MAX_REUSE_INVOCATIONS",
            state.max_cell_invocations.to_string(),
        )
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to start {}", state.worker_command))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("worker stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("worker stdout unavailable"))?;
    let cell = Arc::new(Mutex::new(Cell {
        artifact_sha256: artifact_sha256.clone(),
        child,
        stdin,
        stdout: BufReader::new(stdout),
        invocation_count: 0,
        _live_permit: live_permit,
    }));

    let mut cells = state.cells.lock().await;
    if let Some(existing) = cells.get(key).cloned() {
        let same_generation = {
            let guard = existing.lock().await;
            guard.artifact_sha256 == artifact_sha256
        };
        if same_generation {
            drop(cells);
            let mut unused = cell.lock().await;
            let _ = unused.child.kill().await;
            let _ = unused.child.wait().await;
            return Ok(existing);
        }
        drop(cells);
        let _ = retire_cell(state, key).await;
        cells = state.cells.lock().await;
    }
    cells.insert(key.clone(), cell.clone());
    return Ok(cell);
}
'''
replace_once(old_ensure, new_ensure, "ensure cell generation fence")
replace_once(
    "fn artifact_path(root: &Path, key: &CellKey, filename: &str) -> Result<PathBuf> {",
    '''fn require_regular_file(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {description} at {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{description} must be a regular non-symlink file");
    }
    return Ok(());
}

fn sha256_file(path: &Path) -> Result<String> {
    let file = fs::File::open(path)
        .with_context(|| format!("cannot open V8 worker artifact {}", path.display()))?;
    return sha256_reader(file);
}

fn sha256_reader<R: Read>(mut reader: R) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    return Ok(format!("{:x}", hasher.finalize()));
}

fn artifact_path(root: &Path, key: &CellKey, filename: &str) -> Result<PathBuf> {''',
    "digest helpers",
)
text += '''

#[cfg(test)]
mod generation_digest_tests {
    use super::sha256_reader;
    use std::io::Cursor;

    #[test]
    fn sha256_reader_matches_known_vector() -> anyhow::Result<()> {
        let digest = sha256_reader(Cursor::new(b"abc"))?;
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        return Ok(());
    }
}
'''
path.write_text(text)
