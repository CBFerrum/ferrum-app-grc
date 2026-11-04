//! Governance and risk (FERRUM-ECOSYSTEM-014): risks scored on a matrix with their treatment and
//! acceptance, controls tested with evidence, policies acknowledged by revision, and findings.
//!
//! * `risks`: inherent, current and residual scores, never worse with controls or as targeted;
//!   mitigation names its controls; risks above the tolerance accepted only with an approved
//!   acceptance, which expires.
//! * `controls`: tests of controls in place, effective results with evidence, standing that goes
//!   stale; findings overdue when late, and closed saying how.
//! * `policies`: revisions published with their text, and acknowledgements of a revision.
//!
//! Adapted from CISO Assistant's risk scenarios, applied controls and risk acceptances (AGPL-3.0;
//! docs/PROVENANCE.md). Hooks are registered per entity, so a workspace without the `grc` package
//! never runs them. No framework's text is included, nor any certification claimed.

mod controls;
mod policies;
mod risks;

use chrono::{NaiveDate, Utc};
use ferrum_domain::reports::ReportSource;
use ferrum_kernel::{Ctx, Doc, Error, HookRegistry, Kernel, Result, Tx};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

include!(concat!(env!("OUT_DIR"), "/packages.rs"));
include!(concat!(env!("OUT_DIR"), "/ui.rs"));

/// This app's manifest (`app.yaml`).
pub const MANIFEST: &str = include_str!("../app.yaml");

/// This app's metadata packages, embedded at build time.
pub fn packages() -> std::result::Result<Vec<ferrum_meta::Package>, ferrum_meta::MetaError> {
    ferrum_meta::catalog::load_embedded(EMBEDDED)
}

/// Registers this app's document hooks.
pub fn register(hooks: &mut HookRegistry) {
    hooks
        .register("Risk", Arc::new(risks::RiskHook))
        .register("RiskAcceptance", Arc::new(risks::AcceptanceHook))
        .register("ControlTest", Arc::new(controls::TestHook))
        .register("Finding", Arc::new(controls::FindingHook))
        .register("Policy", Arc::new(policies::PolicyHook));
}

/// This app's reports: none of its own yet.
pub fn reports() -> Vec<Arc<dyn ReportSource>> {
    vec![]
}

/// Upkeep: acceptances expired, controls' standing kept current, and findings overdue.
pub async fn maintenance(k: &Kernel) -> Result<()> {
    maintenance_on(k, Utc::now().date_naive()).await
}

/// [`maintenance`] as of `today`.
pub async fn maintenance_on(k: &Kernel, today: NaiveDate) -> Result<()> {
    let mut tx = k.db.system_tx().await?;
    let tenants: Vec<Uuid> = sqlx::query_scalar("select id from tenant where status = 'active' order by id").fetch_all(&mut *tx).await?;
    tx.commit().await?;
    let mut first_error: Option<Error> = None;
    for tenant in tenants {
        let run = async {
            let schema = k.registry.schema(tenant).await?;
            if !schema.packages.iter().any(|p| p == "grc") {
                return Ok(());
            }
            let ctx = Ctx::system(tenant, schema);
            let mut tx = k.db.tenant_tx(tenant).await?;
            risks::expire(k, &ctx, &mut tx, today).await?;
            controls::upkeep(k, &ctx, &mut tx, today).await?;
            tx.commit().await?;
            Ok::<(), Error>(())
        };
        if let Err(e) = run.await {
            first_error.get_or_insert(e);
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// A document from JSON.
pub(crate) fn obj(v: Value) -> Doc {
    v.as_object().cloned().unwrap_or_default()
}

/// The highest score taken on without an acceptance.
pub(crate) async fn tolerance(tx: &mut Tx, tenant: Uuid) -> Result<i64> {
    let t: Option<i64> =
        sqlx::query_scalar("select tolerance from e_grc_settings where tenant_id = $1 limit 1").bind(tenant).fetch_optional(&mut **tx).await?.flatten();
    Ok(t.unwrap_or(6))
}

/// How many days a control's test is current.
pub(crate) async fn test_every(tx: &mut Tx, tenant: Uuid) -> Result<i64> {
    let t: Option<i64> =
        sqlx::query_scalar("select test_every_days from e_grc_settings where tenant_id = $1 limit 1").bind(tenant).fetch_optional(&mut **tx).await?.flatten();
    Ok(t.unwrap_or(365))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_of_the_matrix() {
        use risks::level;
        assert_eq!((level(1), level(4), level(5), level(9)), ("Low", "Low", "Medium", "Medium"));
        assert_eq!((level(10), level(16), level(20), level(25)), ("High", "High", "Critical", "Critical"));
    }

    #[test]
    fn the_interface_is_a_release_the_platform_takes() {
        let m = ferrum_apps::AppManifest::parse(MANIFEST).expect("app.yaml");
        assert_eq!(m.routes(), vec![("grc".to_string(), vec![])]);
        let files = UI.iter().map(|(p, b)| (p.to_string(), b.to_vec())).collect();
        let ui = ferrum_apps::ui::prepare("grc", files).expect("ui/dist is an interface release");
        assert!(UI.iter().any(|(p, _)| *p == "index.html") && !UI.iter().any(|(p, _)| p.starts_with('.')), "{}", ui.digest);
    }
}
