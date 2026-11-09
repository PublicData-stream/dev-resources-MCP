use super::{BrokerError, Result, crypto::Keyring, identity::PodIdentity, random_id};
use sqlx::{Connection, Row, postgres::PgConnection};

pub(crate) struct Journal {
    pub connection: PgConnection,
    pub broker_id: String,
    cluster_uid: Option<String>,
}
#[derive(Clone)]
pub(crate) struct Record {
    pub intent: String,
    pub identity: PodIdentity,
    pub profile: String,
    pub application_id: String,
    pub description: String,
    pub requested_expiry: i64,
    pub state: String,
    pub access_key: Option<String>,
    pub expires_at: i64,
    pub encryption_key: Option<String>,
    pub ciphertext: Option<Vec<u8>>,
}
impl Record {
    pub fn aad(&self, broker_id: &str, cluster_uid: &str) -> Result<Vec<u8>> {
        serde_json::to_vec(&serde_json::json!([
            broker_id,
            cluster_uid,
            self.intent,
            self.identity.pod_uid,
            self.identity.service_account_uid,
            self.identity.namespace,
            self.identity.service_account,
            self.profile,
            self.application_id,
            self.access_key,
            self.expires_at
        ]))
        .map_err(|_| BrokerError::Integrity)
    }
}
impl Journal {
    pub async fn connect(database_url: &str) -> Result<Self> {
        let mut connection = PgConnection::connect(database_url)
            .await
            .map_err(|_| BrokerError::Unavailable)?;
        let corpus: bool =
            sqlx::query_scalar("SELECT to_regclass('public.devres_captures') IS NOT NULL OR to_regclass('public.devres_schema') IS NOT NULL")
                .fetch_one(&mut connection)
                .await
                .map_err(|_| BrokerError::Unavailable)?;
        if corpus {
            return Err(BrokerError::Forbidden);
        }
        sqlx::query("SET statement_timeout='10s'")
            .execute(&mut connection)
            .await
            .map_err(|_| BrokerError::Unavailable)?;
        let owner: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(685214478215001)")
            .fetch_one(&mut connection)
            .await
            .map_err(|_| BrokerError::Unavailable)?;
        if !owner {
            return Err(BrokerError::Capacity);
        }
        let mut tx = connection
            .begin()
            .await
            .map_err(|_| BrokerError::Unavailable)?;
        sqlx::query("CREATE TABLE IF NOT EXISTS devres_credential_broker_meta(singleton boolean PRIMARY KEY CHECK(singleton), broker_id text NOT NULL, version integer NOT NULL CHECK(version=1))")
            .execute(&mut *tx).await.map_err(|_|BrokerError::Unavailable)?;
        sqlx::query(
            "ALTER TABLE devres_credential_broker_meta ADD COLUMN IF NOT EXISTS cluster_uid text",
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| BrokerError::Unavailable)?;
        sqlx::query("INSERT INTO devres_credential_broker_meta(singleton,broker_id,version) VALUES(true,$1,1) ON CONFLICT(singleton) DO NOTHING")
            .bind(random_id()?).execute(&mut *tx).await.map_err(|_|BrokerError::Unavailable)?;
        sqlx::query("CREATE TABLE IF NOT EXISTS devres_credential_broker_keys(intent text PRIMARY KEY, pod_uid text NOT NULL, namespace text NOT NULL, service_account text NOT NULL, service_account_uid text NOT NULL, pod_name text NOT NULL, token_expires_at bigint NOT NULL, profile text NOT NULL, application_id text NOT NULL, description text NOT NULL UNIQUE, requested_expiry bigint NOT NULL, state text NOT NULL CHECK(state IN ('pending','issued','revoke','revoked')), access_key text UNIQUE, expires_at bigint NOT NULL, encryption_key text, ciphertext bytea, created_at timestamptz NOT NULL DEFAULT now())")
            .execute(&mut *tx).await.map_err(|_|BrokerError::Unavailable)?;
        sqlx::query("CREATE INDEX IF NOT EXISTS devres_broker_active_pod ON devres_credential_broker_keys(pod_uid,expires_at) WHERE state <> 'revoked'")
            .execute(&mut *tx).await.map_err(|_|BrokerError::Unavailable)?;
        let broker_id: String = sqlx::query_scalar(
            "SELECT broker_id FROM devres_credential_broker_meta WHERE singleton AND version=1",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| BrokerError::Integrity)?;
        tx.commit().await.map_err(|_| BrokerError::Unavailable)?;
        Ok(Self {
            connection,
            broker_id,
            cluster_uid: None,
        })
    }
    /// Bind only an empty unbound journal; a previous binding is immutable.
    pub async fn bind_cluster(&mut self, cluster_uid: &str) -> Result<()> {
        self.cluster_uid = None;
        if !super::config::id(cluster_uid) {
            return Err(BrokerError::Invalid);
        }
        let mut tx = self
            .connection
            .begin()
            .await
            .map_err(|_| BrokerError::Unavailable)?;
        let stored: Option<String> = sqlx::query_scalar(
            "SELECT cluster_uid FROM devres_credential_broker_meta WHERE singleton FOR UPDATE",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| BrokerError::Integrity)?;
        if let Some(stored) = stored {
            if stored != cluster_uid {
                tx.rollback().await.map_err(|_| BrokerError::Unavailable)?;
                return Err(BrokerError::Forbidden);
            }
        } else {
            let nonempty: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devres_credential_broker_keys)")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| BrokerError::Unavailable)?;
            if nonempty {
                tx.rollback().await.map_err(|_| BrokerError::Unavailable)?;
                return Err(BrokerError::Forbidden);
            }
            sqlx::query("UPDATE devres_credential_broker_meta SET cluster_uid=$1 WHERE singleton AND cluster_uid IS NULL")
                .bind(cluster_uid).execute(&mut *tx).await.map_err(|_|BrokerError::Unavailable)?;
        }
        tx.commit().await.map_err(|_| BrokerError::Unavailable)?;
        self.cluster_uid = Some(cluster_uid.into());
        Ok(())
    }
    fn bound(&self) -> Result<&str> {
        self.cluster_uid.as_deref().ok_or(BrokerError::Forbidden)
    }
    pub fn aad(&self, row: &Record) -> Result<Vec<u8>> {
        row.aad(&self.broker_id, self.bound()?)
    }
    pub async fn records(&mut self, limit: i64) -> Result<Vec<Record>> {
        self.bound()?;
        let rows=sqlx::query("SELECT intent,pod_uid,namespace,service_account,service_account_uid,pod_name,token_expires_at,profile,application_id,description,requested_expiry,state,access_key,expires_at,encryption_key,ciphertext FROM devres_credential_broker_keys WHERE state <> 'revoked' ORDER BY created_at,intent LIMIT $1")
            .bind(limit+1).fetch_all(&mut self.connection).await.map_err(|_|BrokerError::Unavailable)?;
        if rows.len() as i64 > limit {
            return Err(BrokerError::Capacity);
        }
        rows.into_iter()
            .map(|row| {
                Ok(Record {
                    intent: row.try_get("intent").map_err(|_| BrokerError::Integrity)?,
                    identity: PodIdentity {
                        namespace: row
                            .try_get("namespace")
                            .map_err(|_| BrokerError::Integrity)?,
                        service_account: row
                            .try_get("service_account")
                            .map_err(|_| BrokerError::Integrity)?,
                        service_account_uid: row
                            .try_get("service_account_uid")
                            .map_err(|_| BrokerError::Integrity)?,
                        pod_name: row
                            .try_get("pod_name")
                            .map_err(|_| BrokerError::Integrity)?,
                        pod_uid: row.try_get("pod_uid").map_err(|_| BrokerError::Integrity)?,
                        token_expires_at: row
                            .try_get("token_expires_at")
                            .map_err(|_| BrokerError::Integrity)?,
                    },
                    profile: row.try_get("profile").map_err(|_| BrokerError::Integrity)?,
                    application_id: row
                        .try_get("application_id")
                        .map_err(|_| BrokerError::Integrity)?,
                    description: row
                        .try_get("description")
                        .map_err(|_| BrokerError::Integrity)?,
                    requested_expiry: row
                        .try_get("requested_expiry")
                        .map_err(|_| BrokerError::Integrity)?,
                    state: row.try_get("state").map_err(|_| BrokerError::Integrity)?,
                    access_key: row
                        .try_get("access_key")
                        .map_err(|_| BrokerError::Integrity)?,
                    expires_at: row
                        .try_get("expires_at")
                        .map_err(|_| BrokerError::Integrity)?,
                    encryption_key: row
                        .try_get("encryption_key")
                        .map_err(|_| BrokerError::Integrity)?,
                    ciphertext: row
                        .try_get("ciphertext")
                        .map_err(|_| BrokerError::Integrity)?,
                })
            })
            .collect()
    }
    /// Committed BEFORE the non-idempotent provider call.
    pub async fn intent(
        &mut self,
        identity: &PodIdentity,
        profile: &str,
        app: &str,
        expires: i64,
    ) -> Result<Record> {
        self.bound()?;
        let intent = random_id()?;
        let description = format!("devres-broker:{}:{intent}", self.broker_id);
        sqlx::query("INSERT INTO devres_credential_broker_keys(intent,pod_uid,namespace,service_account,service_account_uid,pod_name,token_expires_at,profile,application_id,description,requested_expiry,state,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending',$11)")
            .bind(&intent).bind(&identity.pod_uid).bind(&identity.namespace).bind(&identity.service_account)
            .bind(&identity.service_account_uid).bind(&identity.pod_name).bind(identity.token_expires_at)
            .bind(profile).bind(app).bind(&description).bind(expires).execute(&mut self.connection).await.map_err(|_|BrokerError::Unavailable)?;
        Ok(Record {
            intent,
            identity: identity.clone(),
            profile: profile.into(),
            application_id: app.into(),
            description,
            requested_expiry: expires,
            state: "pending".into(),
            access_key: None,
            expires_at: expires,
            encryption_key: None,
            ciphertext: None,
        })
    }
    pub async fn issued(
        &mut self,
        row: &Record,
        keyring: &Keyring,
        plaintext: &[u8],
    ) -> Result<()> {
        let cipher = keyring.seal(&self.aad(row)?, plaintext)?;
        let affected=sqlx::query("UPDATE devres_credential_broker_keys SET access_key=$2,expires_at=$3,state='issued',encryption_key=$4,ciphertext=$5 WHERE intent=$1 AND state='pending'")
            .bind(&row.intent).bind(&row.access_key).bind(row.expires_at).bind(&keyring.active).bind(cipher)
            .execute(&mut self.connection).await.map_err(|_|BrokerError::Unavailable)?.rows_affected();
        if affected != 1 {
            return Err(BrokerError::Integrity);
        }
        Ok(())
    }
    pub async fn revoke_pending(&mut self, row: &Record) -> Result<()> {
        self.bound()?;
        sqlx::query("UPDATE devres_credential_broker_keys SET state='revoke',access_key=$2,expires_at=$3 WHERE intent=$1 AND state <> 'revoked'")
            .bind(&row.intent).bind(&row.access_key).bind(row.expires_at).execute(&mut self.connection).await.map_err(|_|BrokerError::Unavailable)?;
        Ok(())
    }
    pub async fn revoked(&mut self, intent: &str) -> Result<()> {
        self.bound()?;
        sqlx::query("UPDATE devres_credential_broker_keys SET state='revoked',ciphertext=NULL,encryption_key=NULL WHERE intent=$1")
            .bind(intent).execute(&mut self.connection).await.map_err(|_|BrokerError::Unavailable)?;
        Ok(())
    }
    pub async fn reseal(&mut self, row: &Record, keys: &Keyring) -> Result<()> {
        if row.ciphertext.is_none() {
            return Ok(());
        }
        let key = row
            .encryption_key
            .as_deref()
            .ok_or(BrokerError::Integrity)?;
        let aad = self.aad(row)?;
        let mut plain = keys.open(
            key,
            &aad,
            row.ciphertext.as_deref().ok_or(BrokerError::Integrity)?,
        )?;
        if key != keys.active {
            let cipher = keys.seal(&aad, &plain)?;
            sqlx::query("UPDATE devres_credential_broker_keys SET encryption_key=$2,ciphertext=$3 WHERE intent=$1")
                .bind(&row.intent).bind(&keys.active).bind(cipher).execute(&mut self.connection).await.map_err(|_|BrokerError::Unavailable)?;
        }
        plain.fill(0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_journal_values_bind_cluster_namespace_and_service_account() {
        let row = Record {
            intent: "intent".into(),
            identity: PodIdentity {
                namespace: "namespace-a".into(),
                service_account: "reader".into(),
                service_account_uid: "sa-uid".into(),
                pod_name: "pod".into(),
                pod_uid: "pod-uid".into(),
                token_expires_at: 1000,
            },
            profile: "profile".into(),
            application_id: "app".into(),
            description: "owned".into(),
            requested_expiry: 900,
            state: "issued".into(),
            access_key: Some("key".into()),
            expires_at: 900,
            encryption_key: None,
            ciphertext: None,
        };
        let keys=Keyring::parse(br#"{"active_key_id":"one","keys":{"one":"0101010101010101010101010101010101010101010101010101010101010101"}}"#).expect("keyring");
        let cipher = keys
            .seal(
                &row.aad("deployment", "cluster-a").expect("AAD"),
                b"protected key",
            )
            .expect("seal");
        assert!(
            keys.open(
                "one",
                &row.aad("deployment", "cluster-b")
                    .expect("different cluster"),
                &cipher
            )
            .is_err()
        );
        for (namespace, account) in [("namespace-b", "reader"), ("namespace-a", "writer")] {
            let mut changed = row.clone();
            changed.identity.namespace = namespace.into();
            changed.identity.service_account = account.into();
            assert!(
                keys.open(
                    "one",
                    &changed
                        .aad("deployment", "cluster-a")
                        .expect("different identity"),
                    &cipher
                )
                .is_err()
            );
        }
        assert_eq!(
            keys.open(
                "one",
                &row.aad("deployment", "cluster-a").expect("same AAD"),
                &cipher
            )
            .expect("open"),
            b"protected key"
        );
    }
    #[tokio::test]
    #[ignore = "requires an isolated DEVRES_TEST_BROKER_DATABASE_URL database"]
    async fn credential_broker_journal_recovers_intents_and_encrypted_credentials() {
        let database = std::env::var("DEVRES_TEST_BROKER_DATABASE_URL")
            .expect("separate fixture broker database URL");
        let mut admission = PgConnection::connect(&database)
            .await
            .expect("fixture database");
        let name: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(&mut admission)
            .await
            .expect("database name");
        assert!(
            name.starts_with("devres_broker_test"),
            "must use the disposable broker database"
        );
        admission.close().await.expect("close admission");
        let mut journal = Journal::connect(&database).await.expect("broker journal");
        assert!(matches!(
            journal.records(32).await,
            Err(BrokerError::Forbidden)
        ));
        journal
            .bind_cluster("fixture-cluster-devres")
            .await
            .expect("first empty-journal binding");
        let identity = PodIdentity {
            namespace: "devres-acceptance".into(),
            service_account: "reader".into(),
            service_account_uid: "sa-uid".into(),
            pod_name: "reader-pod".into(),
            pod_uid: random_id().expect("pod ID"),
            token_expires_at: super::super::now().expect("clock") + 3600,
        };
        let expiry = super::super::now().expect("clock") + 900;
        let mut row = journal
            .intent(
                &identity,
                "profile-fingerprint",
                "11111111-1111-4111-8111-111111111111",
                expiry,
            )
            .await
            .expect("pre-create intent");
        let broker_id = journal.broker_id.clone();
        journal.connection.close().await.expect("release owner");
        let mut journal = Journal::connect(&database).await.expect("recover journal");
        assert_eq!(
            journal.bind_cluster("different-cluster").await,
            Err(BrokerError::Forbidden)
        );
        journal
            .bind_cluster("fixture-cluster-devres")
            .await
            .expect("same cluster restart");
        assert_eq!(journal.broker_id, broker_id);
        let records = journal.records(10000).await.expect("intents");
        assert!(
            records
                .iter()
                .any(|record| record.intent == row.intent && record.state == "pending")
        );
        let keys=Keyring::parse(br#"{"active_key_id":"one","keys":{"one":"0101010101010101010101010101010101010101010101010101010101010101"}}"#).expect("keyring");
        row.access_key = Some(format!("fixture-{}", random_id().expect("key ID")));
        let plaintext=br#"{"AccessKeyId":"sample","SecretAccessKey":"never-plaintext-in-postgres","Expiration":"2026-11-09T12:00:00Z"}"#;
        journal
            .issued(&row, &keys, plaintext)
            .await
            .expect("commit encrypted response");
        journal.connection.close().await.expect("restart owner");
        let mut journal = Journal::connect(&database)
            .await
            .expect("recover credentials");
        journal
            .bind_cluster("fixture-cluster-devres")
            .await
            .expect("bound credential recovery");
        let records = journal.records(10000).await.expect("records");
        let recovered = records
            .iter()
            .find(|record| record.intent == row.intent)
            .expect("issued row");
        let ciphertext = recovered.ciphertext.as_deref().expect("ciphertext");
        assert!(
            !ciphertext
                .windows(b"never-plaintext-in-postgres".len())
                .any(|bytes| bytes == b"never-plaintext-in-postgres")
        );
        assert_eq!(
            keys.open(
                recovered.encryption_key.as_deref().expect("key ID"),
                &journal.aad(recovered).expect("AAD"),
                ciphertext
            )
            .expect("decrypt"),
            plaintext
        );
        journal.revoked(&row.intent).await.expect("revoke");
        let discarded:bool=sqlx::query_scalar("SELECT ciphertext IS NULL AND encryption_key IS NULL FROM devres_credential_broker_keys WHERE intent=$1")
            .bind(&row.intent).fetch_one(&mut journal.connection).await.expect("discard encrypted secret");
        assert!(discarded);
        sqlx::query("UPDATE devres_credential_broker_meta SET cluster_uid=NULL WHERE singleton")
            .execute(&mut journal.connection)
            .await
            .expect("simulate legacy unbound journal");
        journal.connection.close().await.expect("close owner");
        let mut legacy = Journal::connect(&database).await.expect("legacy journal");
        assert_eq!(
            legacy.bind_cluster("fixture-cluster-devres").await,
            Err(BrokerError::Forbidden),
            "nonempty unbound journals cannot silently acquire a cluster"
        );
        sqlx::query("UPDATE devres_credential_broker_meta SET cluster_uid='fixture-cluster-devres' WHERE singleton")
            .execute(&mut legacy.connection).await.expect("restore fixture cluster binding");
        legacy
            .connection
            .close()
            .await
            .expect("close legacy fixture");
        let mut fixture = PgConnection::connect(&database)
            .await
            .expect("fixture admission");
        sqlx::query("CREATE TABLE devres_schema(version integer)")
            .execute(&mut fixture)
            .await
            .expect("synthetic corpus schema marker");
        assert!(
            matches!(
                Journal::connect(&database).await,
                Err(BrokerError::Forbidden)
            ),
            "corpus and broker must never share a database"
        );
        sqlx::query("DROP TABLE devres_schema")
            .execute(&mut fixture)
            .await
            .expect("remove synthetic corpus marker");
        fixture.close().await.expect("close fixture");
    }
}
