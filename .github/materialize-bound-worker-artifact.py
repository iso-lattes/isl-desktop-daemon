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
    "const MAX_WORKER_RESPONSE_BYTES: usize = 4 * 1024 * 1024;\n",
    "const MAX_WORKER_RESPONSE_BYTES: usize = 4 * 1024 * 1024;\nconst MAX_WORKER_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;\n",
    "artifact size constant",
)
replace_once(
    """fn require_regular_file(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {description} at {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{description} must be a regular non-symlink file");
    }
    return Ok(());
}
""",
    """fn require_regular_file(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {description} at {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{description} must be a regular non-symlink file");
    }
    validate_artifact_size(description, metadata.len(), MAX_WORKER_ARTIFACT_BYTES)?;
    return Ok(());
}

fn validate_artifact_size(description: &str, bytes: u64, max_bytes: u64) -> Result<()> {
    if bytes == 0 || bytes > max_bytes {
        bail!("{description} size must be between 1 and {max_bytes} bytes");
    }
    return Ok(());
}
""",
    "bounded regular file",
)
replace_once(
    """    #[tokio::test]
    async fn cell_slot_limit_is_strict() {
""",
    """    #[test]
    fn worker_artifact_size_is_bounded() {
        assert!(validate_artifact_size("worker", 1, MAX_WORKER_ARTIFACT_BYTES).is_ok());
        assert!(
            validate_artifact_size(
                "worker",
                MAX_WORKER_ARTIFACT_BYTES,
                MAX_WORKER_ARTIFACT_BYTES
            )
            .is_ok()
        );
        assert!(validate_artifact_size("worker", 0, MAX_WORKER_ARTIFACT_BYTES).is_err());
        assert!(
            validate_artifact_size(
                "worker",
                MAX_WORKER_ARTIFACT_BYTES + 1,
                MAX_WORKER_ARTIFACT_BYTES
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn cell_slot_limit_is_strict() {
""",
    "artifact size test",
)

path.write_text(text)
