//! Explicit synthetic-only S3 rotation seeder. No collectors or public listeners.
use devres_adapters::{
    PgBlobStore, integrity,
    object_storage::{S3Config, S3Credentials},
};
use devres_application::Store;
use devres_domain::{FetchRequest, FetchResponse, Validators};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx_core::{connection::Connection, row::Row};
use sqlx_postgres::PgConnection;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const REVISION: &str = "a938112b5af87996661ddd91ae68755dc0d579b9";
const BODY_LIMIT: usize = 32768;
const MARKER: &[u8] = b"devres-static-rotation-v1\n";
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    role: String,
    scope: String,
    database_url: String,
    cache_dir: PathBuf,
    state_dir: PathBuf,
    s3: S3Config,
}
fn invalid<T>() -> Result<T> {
    Err("Invalid private synthetic rotation configuration or evidence".into())
}
fn path_checked(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || !path.starts_with("/tmp")
        || path == Path::new("/tmp")
        || path
            .components()
            .any(|p| matches!(p, std::path::Component::ParentDir))
        || path
            .ancestors()
            .any(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()))
    {
        return invalid();
    }
    Ok(())
}
fn uid() -> Result<u32> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|s| s.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "Effective UID unavailable".into())
}
fn private_read(path: &Path) -> Result<Vec<u8>> {
    path_checked(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != uid()?
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
        || meta.len() > 65536
    {
        return invalid();
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return invalid();
    }
    Ok(bytes)
}
fn save_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().ok_or("Missing evidence parent")?)?.sync_all()?;
    Ok(())
}
impl Config {
    fn validate(&self, command: &str) -> Result<()> {
        if self.role != command
            || !matches!(command, "write" | "read")
            || self.scope.len() != 24
            || !self
                .scope
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return invalid();
        }
        self.s3.validate()?;
        if self.s3.endpoint != "https://s3.fr-par.scw.cloud"
            || self.s3.bucket != "dev-resources-mcp"
            || self.s3.region != "fr-par"
            || self.s3.prefix != format!("production/.acceptance/runtime-{}", self.scope)
            || !self.s3.path_style
            || self.s3.allow_http
            || self.s3.ca_file.is_some()
            || self.s3.storage_class.as_deref() != Some("ONEZONE_IA")
            || self.s3.cache_max_bytes != 67108864
        {
            return invalid();
        }
        match &self.s3.credentials {
            S3Credentials::Files {
                access_key_file,
                secret_key_file,
                session_token_file: None,
            } => {
                path_checked(access_key_file)?;
                path_checked(secret_key_file)?;
                if access_key_file.file_name().and_then(|x| x.to_str()) != Some("access-key")
                    || secret_key_file.file_name().and_then(|x| x.to_str()) != Some("secret-key")
                    || access_key_file.parent() != secret_key_file.parent()
                {
                    return invalid();
                }
            }
            _ => return invalid(),
        }
        path_checked(&self.cache_dir)?;
        path_checked(&self.state_dir)?;
        if self.cache_dir.starts_with(&self.state_dir)
            || self.state_dir.starts_with(&self.cache_dir)
        {
            return invalid();
        }
        let db = url::Url::parse(&self.database_url)?;
        if db.scheme() != "postgres"
            || db.path() != format!("/devres_rotation_{}", self.scope)
            || db.query().is_some()
            || db.fragment().is_some()
            || db.username()
                != if command == "write" {
                    "devres_rotation_writer"
                } else {
                    "devres_rotation_reader"
                }
            || db.host_str() != Some("postgres")
        {
            return invalid();
        }
        Ok(())
    }
    fn request(&self) -> FetchRequest {
        FetchRequest {
            key: format!("fixture:static-rotation:{}", self.scope),
            url: format!("https://fixtures.invalid/static-rotation/{}", self.scope),
            ttl_secs: 3600,
            max_bytes: BODY_LIMIT,
            media_type: "text/plain".into(),
        }
    }
    fn body(&self, phase: u8) -> Vec<u8> {
        format!(
            "Synthetic static S3 rotation fixture only.\nscope={}\nphase={}\n",
            self.scope, phase
        )
        .into_bytes()
    }
    fn expected(&self, phase: u8) -> Value {
        let request = self.request();
        let body = self.body(phase);
        let hash = integrity::hash(&body);
        let id = integrity::hash(
            format!(
                "{}\0{}\0{}\0{}",
                request.key, request.url, request.media_type, hash
            )
            .as_bytes(),
        );
        let logical_path = format!("blake3/{}", hash.strip_prefix("blake3:").unwrap_or(&hash));
        let binding_key = format!(
            "{}/bindings/{}.json",
            self.s3.prefix,
            blake3::hash(logical_path.as_bytes()).to_hex()
        );
        json!({"version":1,"release_revision":REVISION,"synthetic":true,"production_acceptance":false,"scope":self.scope,"phase":phase,"capture_id":id,"body_hash":hash,"bytes":body.len(),"object_key":format!("{}/objects/{}",self.s3.prefix,logical_path),"binding_key":binding_key,"store_key":format!("{}/store.json",self.s3.prefix)})
    }
}
fn state_owned(config: &Config) -> Result<()> {
    let meta = std::fs::symlink_metadata(&config.state_dir)?;
    if !meta.is_dir()
        || meta.uid() != uid()?
        || meta.mode() & 0o077 != 0
        || private_read(&config.state_dir.join("owner-v1"))? != MARKER
    {
        return invalid();
    }
    Ok(())
}
fn receipt(config: &Config, phase: u8) -> Result<Value> {
    let value: Value = serde_json::from_slice(&private_read(
        &config.state_dir.join(format!("phase{phase}.json")),
    )?)?;
    let mut identity = value.clone();
    identity
        .as_object_mut()
        .ok_or("Invalid receipt")?
        .remove("archive_control");
    if identity != config.expected(phase)
        || value["archive_control"]["backend"] != "s3"
        || value["archive_control"]["epoch"]
            .as_i64()
            .is_none_or(|n| n <= 0)
        || value["archive_control"]["binding"]
            .as_str()
            .is_none_or(|s| !s.starts_with("blake3:"))
    {
        return invalid();
    }
    Ok(value)
}
async fn archive_state(config: &Config) -> Result<Value> {
    let mut connection = PgConnection::connect(&config.database_url).await?;
    let row=sqlx_core::query::query("SELECT backend,binding,epoch FROM devres_archive_control WHERE singleton AND pending_binding IS NULL AND NOT initializing_s3").fetch_one(&mut connection).await?;
    Ok(
        json!({"backend":row.try_get::<String,_>("backend")?,"binding":row.try_get::<String,_>("binding")?,"epoch":row.try_get::<i64,_>("epoch")?}),
    )
}
async fn run(config: Config, command: &str, phase: Option<u8>) -> Result<()> {
    config.validate(command)?;
    if command == "write" {
        let phase = phase.ok_or("Write requires phase 1 or 2")?;
        if phase == 1 {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&config.state_dir)?;
            save_new(&config.state_dir.join("owner-v1"), MARKER)?;
        }
        state_owned(&config)?;
        if phase == 2 {
            receipt(&config, 1)?;
        } else if phase != 1 {
            return invalid();
        }
        let mut evidence = config.expected(phase);
        // Intent is durable before either database or S3 connection. Ambiguous
        // publication is never retried automatically, including idempotent bytes.
        save_new(
            &config.state_dir.join(format!("phase{phase}-intent.json")),
            &serde_json::to_vec_pretty(&evidence)?,
        )?;
        let store = PgBlobStore::connect_archive_for_maintenance(
            &config.database_url,
            &config.cache_dir,
            Some(config.s3.clone()),
        )
        .await?;
        let control = archive_state(&config).await?;
        if phase == 2 && control != receipt(&config, 1)?["archive_control"] {
            return invalid();
        }
        let published = store
            .publish(
                &config.request(),
                FetchResponse {
                    status: 200,
                    body: config.body(phase),
                    validators: Validators::default(),
                },
                devres_domain::unix_now(),
            )
            .await?;
        if published.capture.id != evidence["capture_id"]
            || published.capture.body_hash != evidence["body_hash"]
            || published.body.as_ref() != config.body(phase).as_slice()
        {
            return invalid();
        }
        if archive_state(&config).await? != control {
            return invalid();
        }
        evidence["archive_control"] = control;
        drop(store); // Releases both the maintenance lifecycle and writer fences.
        save_new(
            &config.state_dir.join(format!("phase{phase}.json")),
            &serde_json::to_vec_pretty(&evidence)?,
        )?;
    } else {
        if phase.is_some() {
            return invalid();
        }
        state_owned(&config)?;
        let records = [receipt(&config, 1)?, receipt(&config, 2)?];
        // A fresh directory ensures this proves remote materialization rather
        // than a successful read of writer or previous-reader cache bytes.
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&config.cache_dir)?;
        let store = PgBlobStore::connect_reader(
            &config.database_url,
            &config.cache_dir,
            Some(config.s3.clone()),
        )
        .await?;
        if !store.is_reader()
            || records[0]["archive_control"] != records[1]["archive_control"]
            || archive_state(&config).await? != records[0]["archive_control"]
        {
            return invalid();
        }
        for (phase, record) in (1u8..=2).zip(records.iter()) {
            let stored = store
                .capture(record["capture_id"].as_str().ok_or("Missing capture")?)
                .await?;
            if stored.body.as_ref() != config.body(phase).as_slice()
                || stored.capture.body_hash != record["body_hash"]
            {
                return invalid();
            }
        }
        let latest = store
            .latest(&config.request().key)
            .await?
            .ok_or("Synthetic head missing")?;
        if latest.stored.capture.id != records[1]["capture_id"]
            || latest.stored.body.as_ref() != config.body(2).as_slice()
        {
            return invalid();
        }
        drop(store);
        save_new(
            &config.cache_dir.join("rotation-read.json"),
            &serde_json::to_vec_pretty(
                &json!({"release_revision":REVISION,"synthetic":true,"production_acceptance":false,"scope":config.scope,"cold_history_both_phases":true,"latest_phase":2,"archive_control":records[0]["archive_control"]}),
            )?,
        )?;
    }
    println!("Synthetic rotation step completed; no production receipt emitted");
    Ok(())
}
async fn entry() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let (command,path,phase)=match args.as_slice(){[command,flag,path] if flag=="--config" && command=="read"=>(command,path,None),[command,flag,path,phase_flag,phase] if command=="write" && flag=="--config" && phase_flag=="--phase" && matches!(phase.as_str(),"1"|"2")=>(command,path,Some(phase.parse()?)),_=>return Err("usage: static-rotation-probe write --config PRIVATE.toml --phase 1|2 | read --config PRIVATE.toml".into())};
    let config: Config = toml::from_str(std::str::from_utf8(&private_read(Path::new(path))?)?)?;
    run(config, command, phase).await
}

#[tokio::main]
async fn main() {
    if entry().await.is_err() {
        eprintln!("Synthetic rotation step failed; private evidence retained");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn config(root: &Path, role: &str) -> Config {
        let scope = "1234567890abcdef12345678";
        toml::from_str(&format!(
            r#"role="{role}"
scope="{scope}"
database_url="postgres://devres_rotation_{}:fixture-only@postgres/devres_rotation_{scope}"
cache_dir="{}/cache"
state_dir="{}/state"
[s3]
endpoint="https://s3.fr-par.scw.cloud"
bucket="dev-resources-mcp"
region="fr-par"
prefix="production/.acceptance/runtime-{scope}"
storage_class="ONEZONE_IA"
cache_max_bytes=67108864
[s3.credentials]
mode="files"
access_key_file="{}/keys/access-key"
secret_key_file="{}/keys/secret-key"
"#,
            if role == "write" { "writer" } else { "reader" },
            root.display(),
            root.display(),
            root.display(),
            root.display()
        ))
        .unwrap()
    }
    #[test]
    fn scope_role_endpoint_and_private_paths_fail_closed_before_io() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let mut candidate = config(root.path(), "write");
        candidate.validate("write").unwrap();
        assert!(candidate.validate("read").is_err());
        candidate.s3.prefix = "production".into();
        assert!(candidate.validate("write").is_err());
        let mut candidate = config(root.path(), "write");
        candidate.s3.endpoint = "https://example.com".into();
        assert!(candidate.validate("write").is_err());
        let mut candidate = config(root.path(), "write");
        candidate.database_url = candidate.database_url.replace("@postgres/", "@production/");
        assert!(candidate.validate("write").is_err());
        let mut candidate = config(root.path(), "read");
        candidate.validate("read").unwrap();
        candidate.cache_dir = candidate.state_dir.clone();
        assert!(candidate.validate("read").is_err());
        assert!(path_checked(Path::new("/tmp/../var/cache")).is_err());
    }
    #[test]
    fn only_two_small_synthetic_identities_are_declared_without_credential_values() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let c = config(root.path(), "write");
        let first = c.expected(1);
        let second = c.expected(2);
        assert_ne!(first["capture_id"], second["capture_id"]);
        assert_ne!(first["object_key"], second["object_key"]);
        for (phase, item) in (1u8..=2).zip([first, second]) {
            assert!(c.body(phase).len() <= BODY_LIMIT);
            assert_eq!(item["body_hash"], integrity::hash(&c.body(phase)));
            assert!(
                item["object_key"]
                    .as_str()
                    .unwrap()
                    .starts_with(&(c.s3.prefix.clone() + "/objects/blake3/"))
            );
            assert_eq!(item["production_acceptance"], false);
            assert!(!item.to_string().contains("fixture-only"));
        }
    }
    #[test]
    fn private_config_rejects_shared_permissions_and_symlink_aliases() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let path = root.path().join("config.toml");
        save_new(&path, b"synthetic fixture").unwrap();
        assert_eq!(private_read(&path).unwrap(), b"synthetic fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_read(&path).is_err());
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(private_read(&alias).is_err());
    }
    #[tokio::test]
    async fn ambiguous_phase_intent_refuses_reentry_without_opening_a_database() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let c = config(root.path(), "write");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&c.state_dir)
            .unwrap();
        save_new(&c.state_dir.join("owner-v1"), MARKER).unwrap();
        let mut first = c.expected(1);
        first["archive_control"] =
            json!({"backend":"s3","epoch":2,"binding":format!("blake3:{}","a".repeat(64))});
        save_new(
            &c.state_dir.join("phase1.json"),
            &serde_json::to_vec(&first).unwrap(),
        )
        .unwrap();
        let intent = c.state_dir.join("phase2-intent.json");
        save_new(&intent, b"ambiguous previous attempt").unwrap();
        assert!(run(c, "write", Some(2)).await.is_err());
        assert_eq!(
            std::fs::read(intent).unwrap(),
            b"ambiguous previous attempt"
        );
        assert!(!root.path().join("cache").exists());
    }
}
