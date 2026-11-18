//! Compliance assessments: how the organisation stands against one framework, a row per assessable requirement.
//! Each row shows what the controls mapped to its requirement say today (all effective: Compliant; none:
//! Non-Compliant; some: Partially; none in place: nothing) beside the assessor's result, which nothing overwrites.
//! The rows come from the framework (Refresh It); the counts and the coverage follow the rows at every save; a
//! completed assessment is kept as it was. Adapted from CISO Assistant's compliance and requirement assessments
//! (designs only).

use crate::obj;
use async_trait::async_trait;
use ferrum_domain::util::{elevated, id, rows, s};
use ferrum_kernel::{Ctx, Doc, DocHook, Error, HookCtx, Kernel, Result, Tx};
use rust_decimal::Decimal;
use serde_json::{Map, Value, json};
use uuid::Uuid;

const NOT_ASSESSED: &str = "Not Assessed";
const COUNTERS: [&str; 7] = ["requirements", "compliant", "partial", "non_compliant", "not_applicable", "not_assessed", "coverage"];

/// The counters and the coverage of a set of results: compliant out of those that apply, two decimals, none when
/// nothing applies.
fn counts<'a>(results: impl Iterator<Item = &'a str>) -> Map<String, Value> {
    let (mut all, mut c, mut p, mut n, mut na, mut open) = (0i64, 0i64, 0i64, 0i64, 0i64, 0i64);
    for r in results {
        all += 1;
        match r {
            "Compliant" => c += 1,
            "Partially Compliant" => p += 1,
            "Non-Compliant" => n += 1,
            "Not Applicable" => na += 1,
            _ => open += 1,
        }
    }
    let applies = all - na;
    let coverage = (applies > 0).then(|| (Decimal::from(c * 100) / Decimal::from(applies)).round_dp(2).to_string());
    obj(json!({"requirements": all, "compliant": c, "partial": p, "non_compliant": n, "not_applicable": na, "not_assessed": open, "coverage": coverage}))
}

/// What the in-place controls mapped to `requirement` say, and how many there are.
async fn suggestion(tx: &mut Tx, tenant: Uuid, requirement: Uuid) -> Result<(i64, &'static str)> {
    let (n, ok): (i64, i64) = sqlx::query_as(
        "select count(*), count(*) filter (where coalesce(c.effective, false)) from e_control__requirements m \
         join e_control c on c.tenant_id = m.tenant_id and c.id = m.parent_id where m.tenant_id = $1 and m.requirement = $2 and c.status = 'In Place'",
    )
    .bind(tenant)
    .bind(requirement)
    .fetch_one(&mut **tx)
    .await?;
    Ok(match (n, ok) {
        (0, _) => (0, NOT_ASSESSED),
        (n, ok) if ok == n => (n, "Compliant"),
        (n, 0) => (n, "Non-Compliant"),
        (n, _) => (n, "Partially Compliant"),
    })
}

/// The assessment's rows: one per assessable requirement of its framework (rows already there kept, new ones
/// appended), each with what its controls say today; written with the counters. Returns the rows and how many
/// were added.
async fn refresh(k: &Kernel, ctx: &Ctx, tx: &mut Tx, assessment: Uuid) -> Result<(Vec<Doc>, i64)> {
    let framework: Uuid = sqlx::query_scalar("select framework from e_compliance_assessment where tenant_id = $1 and id = $2")
        .bind(ctx.tenant)
        .bind(assessment)
        .fetch_one(&mut **tx)
        .await?;
    let kept: Vec<(Uuid, Uuid, Option<String>, Option<String>)> =
        sqlx::query_as("select id, requirement, result, note from e_compliance_assessment__rows where tenant_id = $1 and parent_id = $2 order by idx")
            .bind(ctx.tenant)
            .bind(assessment)
            .fetch_all(&mut **tx)
            .await?;
    let wanted: Vec<Uuid> =
        sqlx::query_scalar("select id from e_requirement where tenant_id = $1 and framework = $2 and coalesce(assessable, true) order by sort_order, ref")
            .bind(ctx.tenant)
            .bind(framework)
            .fetch_all(&mut **tx)
            .await?;
    let mut list: Vec<(Option<Uuid>, Uuid, String, Option<String>)> =
        kept.iter().map(|(rid, q, r, n)| (Some(*rid), *q, r.clone().unwrap_or_else(|| NOT_ASSESSED.into()), n.clone())).collect();
    let added = wanted.iter().filter(|q| !kept.iter().any(|k| k.1 == **q)).count() as i64;
    list.extend(wanted.into_iter().filter(|q| !kept.iter().any(|k| k.1 == *q)).map(|q| (None, q, NOT_ASSESSED.to_string(), None)));
    let mut out = Vec::with_capacity(list.len());
    for (rid, q, result, note) in list {
        let (controls, suggested) = suggestion(tx, ctx.tenant, q).await?;
        let mut row = obj(json!({"requirement": q.to_string(), "result": result, "note": note, "suggested": suggested, "controls": controls}));
        if let Some(rid) = rid {
            row.insert("id".into(), json!(rid.to_string()));
        }
        out.push(row);
    }
    write(k, ctx, tx, assessment, &out).await?;
    Ok((out, added))
}

async fn write(k: &Kernel, ctx: &Ctx, tx: &mut Tx, assessment: Uuid, rows: &[Doc]) -> Result<()> {
    k.set_child_rows_tx(ctx, tx, "ComplianceAssessment", "rows", assessment, rows.to_vec()).await?;
    k.set_values_tx(ctx, tx, "ComplianceAssessment", assessment, counts(rows.iter().map(|r| s(r, "result").unwrap_or(NOT_ASSESSED)))).await
}

pub struct AssessmentHook;

#[async_trait]
impl DocHook for AssessmentHook {
    fn name(&self) -> &'static str {
        "grc.assessment"
    }

    fn fills(&self) -> &'static [&'static str] {
        &COUNTERS
    }

    async fn before_validate(&self, _hc: &mut HookCtx<'_>, doc: &mut Doc) -> Result<()> {
        let n = counts(rows(doc, "rows").iter().map(|r| s(r, "result").unwrap_or(NOT_ASSESSED)));
        doc.extend(n);
        Ok(())
    }

    async fn validate_change(&self, hc: &mut HookCtx<'_>, old: Option<&Doc>, doc: &Doc) -> Result<()> {
        if hc.ctx.is_system {
            return Ok(());
        }
        let Some(old) = old else {
            let framework = id(doc, "framework");
            let off: Option<bool> = sqlx::query_scalar("select disabled from e_framework where tenant_id = $1 and id = $2")
                .bind(hc.ctx.tenant)
                .bind(framework)
                .fetch_optional(&mut **hc.tx)
                .await?
                .flatten();
            if off == Some(true) {
                return Err(Error::field("framework", "is switched off"));
            }
            if !rows(doc, "rows").is_empty() {
                return Err(Error::field("rows", "rows come from the framework: use Refresh It"));
            }
            return Ok(());
        };
        if s(old, "status") == Some("Complete") {
            return Err(Error::invalid("a completed assessment is kept as it was"));
        }
        let pairs = |d: &Doc| {
            let mut v: Vec<(Option<Uuid>, Option<Uuid>)> = rows(d, "rows").iter().map(|r| (id(r, "id"), id(r, "requirement"))).collect();
            v.sort();
            v
        };
        if pairs(old) != pairs(doc) || id(old, "framework") != id(doc, "framework") {
            return Err(Error::field("rows", "rows come from the framework: use Refresh It"));
        }
        Ok(())
    }

    async fn after_save(&self, hc: &mut HookCtx<'_>, doc: &Doc, old: Option<&Doc>) -> Result<()> {
        if old.is_none()
            && let Some(me) = id(doc, "id")
        {
            refresh(hc.kernel, &elevated(hc.ctx), hc.tx, me).await?;
        }
        Ok(())
    }

    async fn action(&self, hc: &mut HookCtx<'_>, name: &str, doc: &Doc, _params: &Value) -> Result<Option<Value>> {
        let me = id(doc, "id").ok_or_else(|| Error::internal("an assessment without an id"))?;
        let system = elevated(hc.ctx);
        match name {
            "refresh_assessment" => {
                let (rows, added) = refresh(hc.kernel, &system, hc.tx, me).await?;
                Ok(Some(json!({"rows": rows.len(), "added": added})))
            }
            "accept_suggestions" => {
                let (mut rows, _) = refresh(hc.kernel, &system, hc.tx, me).await?;
                let mut taken = 0;
                for r in rows.iter_mut() {
                    let suggested = s(r, "suggested").unwrap_or(NOT_ASSESSED).to_string();
                    if s(r, "result") == Some(NOT_ASSESSED) && suggested != NOT_ASSESSED {
                        r.insert("result".into(), json!(suggested));
                        taken += 1;
                    }
                }
                write(hc.kernel, &system, hc.tx, me, &rows).await?;
                Ok(Some(json!({"taken": taken})))
            }
            "complete_assessment" => {
                let (rows, _) = refresh(hc.kernel, &system, hc.tx, me).await?;
                let open = rows.iter().filter(|r| s(r, "result").unwrap_or(NOT_ASSESSED) == NOT_ASSESSED).count();
                if open > 0 {
                    return Err(Error::invalid(format!("{open} requirements are not assessed")));
                }
                let coverage = counts(rows.iter().map(|r| s(r, "result").unwrap_or(NOT_ASSESSED)))["coverage"].clone();
                let today = hc.ctx.today().to_string();
                hc.kernel.set_values_tx(&system, hc.tx, "ComplianceAssessment", me, obj(json!({"status": "Complete", "completed_on": today}))).await?;
                Ok(Some(json!({"status": "Complete", "coverage": coverage})))
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::counts;

    #[test]
    fn coverage_is_compliant_out_of_what_applies() {
        let c = counts(["Compliant", "Compliant", "Partially Compliant", "Not Applicable"].into_iter());
        assert_eq!((c["requirements"].clone(), c["coverage"].clone()), (4.into(), "66.67".into()));
        assert!(counts(["Not Applicable"].into_iter())["coverage"].is_null());
    }
}
