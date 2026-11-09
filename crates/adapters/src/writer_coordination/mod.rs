//! Private, typed source acquisition. Destinations and validation are reconstructed here.
pub(crate) mod retained_git;
use devres_application::{
    Retrieval,
    acquisition::{Acquisition, WriterEffect},
    attribution_runtime::AttributionRuntime,
};
use devres_domain::{Capture, Error, FetchRequest, Result};
use std::sync::Arc;

pub struct WriterCoordinator {
    retrieval: Arc<Retrieval>,
    rfc: Arc<crate::rfc::RfcCorpus>,
    crates: Arc<crate::crates_io::CrateCorpus>,
    attribution: Arc<AttributionRuntime>,
}
impl WriterCoordinator {
    pub fn new(
        retrieval: Arc<Retrieval>,
        rfc: Arc<crate::rfc::RfcCorpus>,
        crates: Arc<crate::crates_io::CrateCorpus>,
        attribution: Arc<AttributionRuntime>,
    ) -> Self {
        Self {
            retrieval,
            rfc,
            crates,
            attribution,
        }
    }
    pub async fn acquire(&self, operation: Acquisition) -> Result<Capture> {
        let stored = match &operation {
            Acquisition::CrateSearch { .. }
            | Acquisition::CrateIndex { .. }
            | Acquisition::CrateArchive { .. } => {
                crate::crates_io::packages::writer_acquire(&self.retrieval, &operation).await?
            }
            Acquisition::NpmSearch { .. }
            | Acquisition::NpmMetadata { .. }
            | Acquisition::NpmArchive { .. } => {
                crate::npm::writer_acquire(self.retrieval.clone(), &operation).await?
            }
            Acquisition::RfcCatalogue => {
                self.retrieval
                    .get_validated(
                        FetchRequest {
                            key: "rfc:index".into(),
                            url: crate::rfc::corpus::INDEX_URL.into(),
                            ttl_secs: 86400,
                            max_bytes: 64 * 1024 * 1024,
                            media_type: "application/xml".into(),
                        },
                        &crate::rfc::source::Validator,
                    )
                    .await?
            }
            Acquisition::RfcErrata => {
                self.retrieval
                    .get_validated(
                        FetchRequest {
                            key: "rfc:errata".into(),
                            url: crate::rfc::corpus::ERRATA_URL.into(),
                            ttl_secs: self.rfc.writer_config().errata_refresh_secs,
                            max_bytes: 64 * 1024 * 1024,
                            media_type: "application/json".into(),
                        },
                        &crate::rfc::source::Validator,
                    )
                    .await?
            }
            Acquisition::RfcRepresentation { number, format } => {
                if *number == 0 || *number > 999_999 {
                    return Err(Error::invalid("Invalid RFC number."));
                }
                let media_type = crate::rfc::corpus::media_type(format)?;
                self.retrieval
                    .get_validated(
                        FetchRequest {
                            key: crate::rfc::corpus::representation_key(*number, format, "https"),
                            url: crate::rfc::corpus::representation_url(*number, format),
                            ttl_secs: 86400,
                            max_bytes: crate::rfc::corpus::BODY_LIMIT,
                            media_type: media_type.into(),
                        },
                        &crate::rfc::source::Validator,
                    )
                    .await?
            }
            Acquisition::RustsecHead { force } => {
                crate::rustsec::corpus::writer_head(&self.retrieval, *force).await?
            }
            Acquisition::RustsecBundle { revision } => {
                if revision.len() != 40
                    || !revision
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                {
                    return Err(Error::invalid("Invalid RustSec revision."));
                }
                self.retrieval
                    .get(FetchRequest {
                        key: format!("rustsec:bundle:{revision}"),
                        url: format!(
                            "https://codeload.github.com/RustSec/advisory-db/tar.gz/{revision}"
                        ),
                        ttl_secs: 365 * 86400,
                        max_bytes: crate::archive::MAX_COMPRESSED,
                        media_type: "application/gzip".into(),
                    })
                    .await?
            }
        };
        Ok(stored.capture)
    }
    pub async fn effect(&self, operation: WriterEffect) -> Result<()> {
        match operation {
            WriterEffect::RfcCatalogue => {
                self.rfc.writer_catalogue().await?;
            }
            WriterEffect::RfcErrata => {
                self.rfc.refresh_errata().await?;
            }
            WriterEffect::RfcRefreshPartial => self.rfc.refresh_partial().await?,
            WriterEffect::RfcForeground {
                number,
                format,
                capture,
            } => {
                let stored = self.retrieval.read_capture(&capture).await?;
                crate::rfc::corpus::media_type(&format)?;
                if stored.capture.key
                    != crate::rfc::corpus::representation_key(number, &format, "https")
                    || stored.capture.source_url
                        != crate::rfc::corpus::representation_url(number, &format)
                {
                    return Err(Error::integrity(
                        "RFC foreground receipt identity mismatch.",
                    ));
                }
                self.rfc
                    .record_foreground(number, &format, &stored.capture)
                    .await?;
            }
            WriterEffect::AttributionEnqueue { target } => {
                self.attribution.enqueue_public(&target).await?
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl devres_application::acquisition::AcquisitionDelegate for WriterCoordinator {
    async fn acquire(&self, operation: Acquisition) -> Result<Capture> {
        WriterCoordinator::acquire(self, operation).await
    }
    async fn effect(&self, operation: WriterEffect) -> Result<()> {
        WriterCoordinator::effect(self, operation).await
    }
    async fn source_status(
        &self,
        source: devres_application::acquisition::SourceStatus,
    ) -> Result<serde_json::Value> {
        match source {
            devres_application::acquisition::SourceStatus::Rfc => self.rfc.status().await,
            devres_application::acquisition::SourceStatus::Crates => self.crates.status().await,
        }
    }
    async fn attribution_status(&self) -> Result<serde_json::Value> {
        devres_application::attribution_gate::AttributionGate::status(self.attribution.as_ref())
            .await
    }
    async fn rfc_snapshot(&self) -> Result<String> {
        Ok(self.rfc.publish_snapshot().await?.id)
    }
}
