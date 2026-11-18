//! Governance and risk (FERRUM-ECOSYSTEM-014): risks scored on a matrix with their treatment and
//! acceptance, controls tested with evidence, policies acknowledged by revision, and findings.
//!
//! * `risks`: inherent, current and residual scores, never worse with controls or as targeted;
//!   mitigation names its controls; risks above the tolerance accepted only with an approved
//!   acceptance, which expires.
//! * `controls`: tests of controls in place, effective results with evidence, standing that goes
//!   stale; findings overdue when late, and closed saying how.
//! * `policies`: revisions published with their text, and acknowledgements of a revision.
//! * `frameworks`: requirements in a tree by reference, and the requirements a control answers.
//! * `assessments`: a framework assessed requirement by requirement, beside what the controls say, and coverage.
//!
//! Adapted from CISO Assistant's risk scenarios, applied controls, risk acceptances, frameworks and
//! requirement nodes (AGPL-3.0; docs/PROVENANCE.md). Hooks are registered per entity, so a workspace
//! without the `grc` package never runs them. No framework's text is in this code, nor any
//! certification claimed: frameworks are data, a sheet or a library package of seed records.

mod assessments;
mod controls;
mod frameworks;
mod policies;
mod risks;

use chrono::NaiveDate;
use ferrum_domain::reports::ReportSource;
use ferrum_kernel::messages::{Message, Recipient};
use ferrum_kernel::{Ctx, Doc, HookRegistry, Kernel, Result, Tx};
use serde_json::{Map, Value};
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
        .register("GrcSettings", Arc::new(risks::SettingsHook))
        .register("ControlTest", Arc::new(controls::TestHook))
        .register("Control", Arc::new(frameworks::ControlHook))
        .register("Requirement", Arc::new(frameworks::RequirementHook))
        .register("ComplianceAssessment", Arc::new(assessments::AssessmentHook))
        .register("Finding", Arc::new(controls::FindingHook))
        .register("Policy", Arc::new(policies::PolicyHook));
}

/// This app's reports: none of its own yet.
pub fn reports() -> Vec<Arc<dyn ReportSource>> {
    vec![]
}

/// One workspace's upkeep, which the platform runs about once a minute where GRC is installed, on whichever replica is
/// free, and may run again: acceptances expired, controls' standing kept current, findings overdue, policies'
/// audiences asked and reminded, and their people told, each once, on the workspace's own day.
pub async fn maintenance(k: &Kernel, tenant: Uuid) -> Result<()> {
    upkeep(k, tenant, None).await
}

/// [`maintenance`] as if the workspace's day were `today`.
pub async fn maintenance_on(k: &Kernel, tenant: Uuid, today: NaiveDate) -> Result<()> {
    upkeep(k, tenant, Some(today)).await
}

async fn upkeep(k: &Kernel, tenant: Uuid, on: Option<NaiveDate>) -> Result<()> {
    let schema = k.registry.schema(tenant).await?;
    let ctx = Ctx::system(tenant, schema);
    let today = on.unwrap_or_else(|| ctx.today());
    let mut tx = k.db.tenant_tx(tenant).await?;
    risks::reband(k, &ctx, &mut tx).await?;
    risks::expire(k, &ctx, &mut tx, today).await?;
    controls::upkeep(k, &ctx, &mut tx, today).await?;
    let days = reminder_days(&mut tx, tenant).await?;
    if days > 0 {
        risks::remind(k, &ctx, &mut tx, today, days).await?;
        controls::remind(k, &ctx, &mut tx, today, days).await?;
    }
    policies::upkeep(k, &ctx, &mut tx, today, days).await?;
    tx.commit().await?;
    Ok(())
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

/// The workspace's matrix: each axis scored from 1 to `scale`, and the current scores at which a risk becomes
/// Medium, High and Critical. Settings saved before the matrix existed, or none: five points with 5, 10 and 17.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Matrix {
    pub scale: i64,
    pub medium_from: i64,
    pub high_from: i64,
    pub critical_from: i64,
}

impl Default for Matrix {
    fn default() -> Self {
        Matrix { scale: 5, medium_from: 5, high_from: 10, critical_from: 17 }
    }
}

pub(crate) async fn matrix(tx: &mut Tx, tenant: Uuid) -> Result<Matrix> {
    let row: Option<(Option<i64>, Option<i64>, Option<i64>, Option<i64>)> =
        sqlx::query_as("select scale::bigint, medium_from::bigint, high_from::bigint, critical_from::bigint from e_grc_settings where tenant_id = $1 limit 1")
            .bind(tenant)
            .fetch_optional(&mut **tx)
            .await?;
    let d = Matrix::default();
    Ok(row.map_or(d, |(s, m, h, c)| Matrix {
        scale: s.unwrap_or(d.scale),
        medium_from: m.unwrap_or(d.medium_from),
        high_from: h.unwrap_or(d.high_from),
        critical_from: c.unwrap_or(d.critical_from),
    }))
}

/// How many days a control's test is current.
pub(crate) async fn test_every(tx: &mut Tx, tenant: Uuid) -> Result<i64> {
    let t: Option<i64> =
        sqlx::query_scalar("select test_every_days from e_grc_settings where tenant_id = $1 limit 1").bind(tenant).fetch_optional(&mut **tx).await?.flatten();
    Ok(t.unwrap_or(365))
}

/// How many days ahead people are reminded; 0: never.
pub(crate) async fn reminder_days(tx: &mut Tx, tenant: Uuid) -> Result<i64> {
    let t: Option<i64> = sqlx::query_scalar("select reminder_days::bigint from e_grc_settings where tenant_id = $1 limit 1")
        .bind(tenant)
        .fetch_optional(&mut **tx)
        .await?
        .flatten();
    Ok(t.unwrap_or(14))
}

/// A message about a record to the addresses given, each once; none, nothing is sent.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn tell(
    k: &Kernel,
    ctx: &Ctx,
    tx: &mut Tx,
    template: &str,
    entity: &str,
    record: Uuid,
    to: Vec<Option<String>>,
    values: Map<String, Value>,
) -> Result<()> {
    let mut people: Vec<String> = to.into_iter().flatten().map(|e| e.trim().to_lowercase()).filter(|e| !e.is_empty()).collect();
    people.sort();
    people.dedup();
    if people.is_empty() {
        return Ok(());
    }
    let m = Message {
        template: template.into(),
        entity: Some(entity.into()),
        record: Some(record),
        to: people.iter().map(|e| Recipient::address(e)).collect(),
        values,
        ..Default::default()
    };
    ferrum_kernel::messages::send(k, tx, ctx, &m).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A framework library is a package of seed records on `grc`: the README's example, and the ones shipped here.
    #[test]
    fn a_library_package_is_valid() {
        let yaml = "package: grc_lib_example\nversion: 0.1.0\nlabel: Example framework\ndepends: [grc]\nseed:\n  - entity: Framework\n    key: [framework_name]\n    records: [{framework_name: Example Framework, edition: \"1\"}]\n  - entity: Requirement\n    key: [framework, ref]\n    records:\n      - {framework: \"@Framework:framework_name=Example Framework\", ref: \"1\", title: Governance, assessable: false, sort_order: 1}\n      - {framework: \"@Framework:framework_name=Example Framework\", ref: \"1.1\", title: A policy exists, parent_ref: \"1\", sort_order: 2}\n";
        let example = ferrum_meta::catalog::load_embedded(&[("grc_lib_example", "package.yaml", yaml)]).expect("the example").remove(0);
        let mut all = ferrum_domain::packages().expect("platform packages");
        all.extend(packages().expect("app packages").into_iter().filter(|p| !p.manifest.depends.iter().any(|d| d == "itsm")));
        all.push(example);
        let catalog = ferrum_meta::Catalog::from_packages(all).unwrap_or_else(|e| panic!("{e}"));
        let names = ["grc_lib_example", "grc_lib_nist_csf"].map(String::from).to_vec();
        let schema = ferrum_meta::effective::build(&catalog, &catalog.closure(&names).unwrap(), &[], 1).unwrap_or_else(|e| panic!("{e}"));
        assert!(schema.warnings.is_empty(), "{:?}", schema.warnings);
    }

    /// The ITSM connector against a stand-in `itsm` package holding ConfigurationItem, as Contracts tests its own.
    #[test]
    fn the_package_and_its_connector_are_valid() {
        let entities =
            "- name: ConfigurationItem\n  label: Configuration Item\n  kind: master\n  title_field: ci_name\n  fields:\n    - {name: ci_name, type: data}\n";
        let stand_in = ferrum_meta::catalog::load_embedded(&[
            ("itsm", "package.yaml", "package: itsm\nversion: 0.0.1\ndepends: [core]\n"),
            ("itsm", "entities/e.yaml", entities),
        ])
        .expect("stand-in")
        .remove(0);
        let mut all = ferrum_domain::packages().expect("platform packages");
        all.extend(packages().expect("app packages"));
        all.push(stand_in);
        let catalog = ferrum_meta::Catalog::from_packages(all).unwrap_or_else(|e| panic!("{e}"));
        let with = ferrum_meta::effective::build(&catalog, &catalog.closure(&["grc".to_string(), "grc_itsm".to_string()]).unwrap(), &[], 1)
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(with.warnings.is_empty(), "{:?}", with.warnings);
        assert!(with.entity("Control").unwrap().field("itsm_ci").is_some() && with.entity("RiskAsset").unwrap().field("itsm_ci").is_some());
        let alone = ferrum_meta::effective::build(&catalog, &catalog.closure(&["grc".to_string()]).unwrap(), &[], 1).unwrap();
        assert!(alone.entity("Control").unwrap().field("itsm_ci").is_none() && alone.entity("RiskAsset").unwrap().field("itsm_ci").is_none());
    }

    #[test]
    fn levels_of_the_matrix() {
        let level = |s| risks::level(s, &Matrix::default());
        assert_eq!((level(1), level(4), level(5), level(9)), ("Low", "Low", "Medium", "Medium"));
        assert_eq!((level(10), level(16), level(20), level(25)), ("High", "High", "Critical", "Critical"));
    }

    #[test]
    fn levels_follow_the_bands() {
        let m = Matrix { scale: 3, medium_from: 3, high_from: 5, critical_from: 8 };
        let level = |s| risks::level(s, &m);
        assert_eq!((level(1), level(2), level(3), level(4)), ("Low", "Low", "Medium", "Medium"));
        assert_eq!((level(5), level(7), level(8), level(9)), ("High", "High", "Critical", "Critical"));
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
