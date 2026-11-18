//! Business continuity: processes with their recovery objectives, plans that cover them, and plan tests. A plan is
//! current while its latest test by day passed and is within the plan's interval, as a control is effective while
//! its last test is (`controls::standing`, written again here for plans). A test's recovery is measured against the
//! shortest recovery time of the plan's processes. Objectives are hours a workspace types; no standard's tiers.

use crate::obj;
use async_trait::async_trait;
use chrono::{Duration, NaiveDate};
use ferrum_domain::util::{elevated, id, rows, s};
use ferrum_kernel::{Ctx, Doc, DocHook, Error, HookCtx, Kernel, Result, Tx};
use serde_json::{Value, json};
use uuid::Uuid;

fn n(doc: &Doc, k: &str) -> Option<i64> {
    doc.get(k).and_then(Value::as_i64)
}

pub struct ProcessHook;

#[async_trait]
impl DocHook for ProcessHook {
    fn name(&self) -> &'static str {
        "grc.process"
    }

    async fn validate(&self, _hc: &mut HookCtx<'_>, doc: &Doc) -> Result<()> {
        if let (Some(rto), Some(longest)) = (n(doc, "recovery_time_hours"), n(doc, "longest_outage_hours"))
            && rto > longest
        {
            return Err(Error::field("recovery_time_hours", "is no longer than the longest outage"));
        }
        Ok(())
    }
}

pub struct PlanHook;

#[async_trait]
impl DocHook for PlanHook {
    fn name(&self) -> &'static str {
        "grc.plan"
    }

    async fn validate(&self, _hc: &mut HookCtx<'_>, doc: &Doc) -> Result<()> {
        let listed: Vec<Uuid> = rows(doc, "processes").iter().filter_map(|r| id(r, "process")).collect();
        if listed.iter().enumerate().any(|(i, p)| listed[..i].contains(p)) {
            return Err(Error::field("processes", "a process is listed once"));
        }
        Ok(())
    }
}

/// A plan's standing from its latest test as of `today`.
async fn plan_standing(k: &Kernel, ctx: &Ctx, tx: &mut Tx, plan: Uuid, today: NaiveDate) -> Result<()> {
    let last: Option<(NaiveDate, String, Option<i64>)> = sqlx::query_as(
        "select t.tested_on, t.result, p.test_every_days::bigint from e_plan_test t join e_continuity_plan p on p.tenant_id = t.tenant_id and p.id = t.plan \
         where t.tenant_id = $1 and t.plan = $2 order by t.tested_on desc, t.created_at desc limit 1",
    )
    .bind(ctx.tenant)
    .bind(plan)
    .fetch_optional(&mut **tx)
    .await?;
    let values = match last {
        Some((on, result, every)) => {
            let passed = result == "Passed" || result == "Passed With Findings";
            json!({"last_tested_on": on.to_string(), "last_result": result, "current": passed && on + Duration::days(every.unwrap_or(365)) >= today})
        }
        None => json!({"last_tested_on": null, "last_result": null, "current": false}),
    };
    k.set_values_tx(ctx, tx, "ContinuityPlan", plan, obj(values)).await
}

pub struct PlanTestHook;

#[async_trait]
impl DocHook for PlanTestHook {
    fn name(&self) -> &'static str {
        "grc.plan_test"
    }

    fn fills(&self) -> &'static [&'static str] {
        &["tester", "met_recovery_time"]
    }

    async fn before_validate(&self, hc: &mut HookCtx<'_>, doc: &mut Doc) -> Result<()> {
        if s(doc, "tester").is_none() {
            doc.insert("tester".into(), json!(hc.ctx.email));
        }
        let shortest: Option<i64> = sqlx::query_scalar(
            "select min(b.recovery_time_hours)::bigint from e_continuity_plan__processes pp join e_business_process b on b.tenant_id = pp.tenant_id and b.id = pp.process \
             where pp.tenant_id = $1 and pp.parent_id = $2",
        )
        .bind(hc.ctx.tenant)
        .bind(id(doc, "plan"))
        .fetch_one(&mut **hc.tx)
        .await?;
        let met = matches!((n(doc, "recovered_in_hours"), shortest), (Some(took), Some(limit)) if took <= limit);
        doc.insert("met_recovery_time".into(), json!(met));
        Ok(())
    }

    async fn validate(&self, hc: &mut HookCtx<'_>, doc: &Doc) -> Result<()> {
        if s(doc, "tested_on").is_some_and(|d| d > hc.ctx.today().to_string().as_str()) {
            return Err(Error::field("tested_on", "is today or before"));
        }
        let status: Option<String> = sqlx::query_scalar("select status from e_continuity_plan where tenant_id = $1 and id = $2")
            .bind(hc.ctx.tenant)
            .bind(id(doc, "plan"))
            .fetch_optional(&mut **hc.tx)
            .await?
            .flatten();
        if status.as_deref() != Some("In Force") {
            return Err(Error::field("plan", "is tested once it is in force"));
        }
        if s(doc, "result") == Some("Passed") && !rows(doc, "evidence").iter().any(|e| s(e, "file").is_some()) {
            return Err(Error::field("evidence", "a passed test has its evidence"));
        }
        Ok(())
    }

    async fn after_save(&self, hc: &mut HookCtx<'_>, doc: &Doc, _old: Option<&Doc>) -> Result<()> {
        let Some(plan) = id(doc, "plan") else { return Ok(()) };
        plan_standing(hc.kernel, &elevated(hc.ctx), hc.tx, plan, hc.ctx.today()).await
    }
}

/// Every current plan's standing as of `today`.
pub(crate) async fn upkeep(k: &Kernel, ctx: &Ctx, tx: &mut Tx, today: NaiveDate) -> Result<()> {
    let current: Vec<Uuid> =
        sqlx::query_scalar("select id from e_continuity_plan where tenant_id = $1 and coalesce(current, false)").bind(ctx.tenant).fetch_all(&mut **tx).await?;
    for plan in current {
        plan_standing(k, ctx, tx, plan, today).await?;
    }
    Ok(())
}
