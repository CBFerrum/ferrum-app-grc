//! Controls and their tests. A test is of a control in place, on a day not in the future, by
//! whoever records it; an effective result needs its evidence. The control's last test is its
//! latest by day; the control is effective while that test was effective and is still current.
//! Upkeep marks controls whose last test has gone stale as no longer effective. A finding left
//! open past its day is overdue; closed, it says how it was fixed. Its owner is told before it is due and once it
//! is overdue.

use crate::{obj, tell, test_every};
use async_trait::async_trait;
use chrono::{Duration, NaiveDate};
use ferrum_domain::util::{b, elevated, id, rows, s};
use ferrum_kernel::{Ctx, Doc, DocHook, Error, HookCtx, Kernel, Result, Tx};
use serde_json::{Map, Value, json};
use uuid::Uuid;

/// A control's standing from its latest test as of `today`.
async fn standing(k: &Kernel, ctx: &Ctx, tx: &mut Tx, control: Uuid, today: NaiveDate) -> Result<()> {
    let last: Option<(NaiveDate, String)> =
        sqlx::query_as("select tested_on, result from e_control_test where tenant_id = $1 and control = $2 order by tested_on desc, created_at desc limit 1")
            .bind(ctx.tenant)
            .bind(control)
            .fetch_optional(&mut **tx)
            .await?;
    let every = test_every(tx, ctx.tenant).await?;
    let values = match last {
        Some((on, result)) => {
            json!({"last_tested_on": on.to_string(), "last_result": result, "effective": result == "Effective" && on + Duration::days(every) >= today})
        }
        None => json!({"last_tested_on": null, "last_result": null, "effective": false}),
    };
    k.set_values_tx(ctx, tx, "Control", control, obj(values)).await
}

pub struct TestHook;

#[async_trait]
impl DocHook for TestHook {
    fn name(&self) -> &'static str {
        "grc.control_test"
    }

    fn fills(&self) -> &'static [&'static str] {
        &["tester"]
    }

    async fn before_validate(&self, hc: &mut HookCtx<'_>, doc: &mut Doc) -> Result<()> {
        if s(doc, "tester").is_none() {
            doc.insert("tester".into(), json!(hc.ctx.email));
        }
        Ok(())
    }

    async fn validate(&self, hc: &mut HookCtx<'_>, doc: &Doc) -> Result<()> {
        if s(doc, "tested_on").is_some_and(|d| d > hc.ctx.today().to_string().as_str()) {
            return Err(Error::field("tested_on", "is today or before"));
        }
        let status: Option<String> = sqlx::query_scalar("select status from e_control where tenant_id = $1 and id = $2")
            .bind(hc.ctx.tenant)
            .bind(id(doc, "control"))
            .fetch_optional(&mut **hc.tx)
            .await?
            .flatten();
        if status.as_deref() != Some("In Place") {
            return Err(Error::field("control", "is tested once it is in place"));
        }
        if s(doc, "result") == Some("Effective") && !rows(doc, "evidence").iter().any(|e| s(e, "file").is_some()) {
            return Err(Error::field("evidence", "an effective result has its evidence"));
        }
        Ok(())
    }

    async fn after_save(&self, hc: &mut HookCtx<'_>, doc: &Doc, _old: Option<&Doc>) -> Result<()> {
        let Some(control) = id(doc, "control") else { return Ok(()) };
        standing(hc.kernel, &elevated(hc.ctx), hc.tx, control, hc.ctx.today()).await
    }
}

/// Every control's standing as of `today`, and findings past their day marked overdue.
pub(crate) async fn upkeep(k: &Kernel, ctx: &Ctx, tx: &mut Tx, today: NaiveDate) -> Result<()> {
    let effective: Vec<Uuid> =
        sqlx::query_scalar("select id from e_control where tenant_id = $1 and coalesce(effective, false)").bind(ctx.tenant).fetch_all(&mut **tx).await?;
    for control in effective {
        standing(k, ctx, tx, control, today).await?;
    }
    let late: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "select id, owner from e_finding where tenant_id = $1 and status <> 'Closed' and due_on < $2 and not coalesce(overdue, false) order by id for update",
    )
    .bind(ctx.tenant)
    .bind(today)
    .fetch_all(&mut **tx)
    .await?;
    for (finding, owner) in late {
        k.set_values_tx(ctx, tx, "Finding", finding, obj(json!({"overdue": true}))).await?;
        tell(k, ctx, tx, "grc.finding_overdue", "Finding", finding, vec![owner], Map::new()).await?;
    }
    Ok(())
}

/// Open findings due within `days`, their owner told once for the day they are due.
pub(crate) async fn remind(k: &Kernel, ctx: &Ctx, tx: &mut Tx, today: NaiveDate, days: i64) -> Result<()> {
    let due: Vec<(Uuid, Option<String>, NaiveDate)> = sqlx::query_as(
        "select id, owner, due_on from e_finding where tenant_id = $1 and status <> 'Closed' \
         and due_on >= $2 and due_on <= $3 and reminded_for is distinct from due_on order by id for update",
    )
    .bind(ctx.tenant)
    .bind(today)
    .bind(today + Duration::days(days))
    .fetch_all(&mut **tx)
    .await?;
    for (finding, owner, on) in due {
        tell(k, ctx, tx, "grc.finding_due", "Finding", finding, vec![owner], Map::new()).await?;
        k.set_values_tx(ctx, tx, "Finding", finding, obj(json!({"reminded_for": on.to_string()}))).await?;
    }
    Ok(())
}

/// A finding that needs a retest names an effective test of its own control, made on or after the day it was raised.
async fn retested(hc: &mut HookCtx<'_>, doc: &Doc) -> Result<()> {
    let Some(control) = id(doc, "control") else {
        return Err(Error::field("control", "a finding that needs a retest names its control"));
    };
    let Some(retest) = id(doc, "retest") else {
        return Err(Error::field("retest", "it closes with the test that showed the fix works"));
    };
    let test: Option<(Option<Uuid>, Option<String>, Option<NaiveDate>)> =
        sqlx::query_as("select control, result, tested_on from e_control_test where tenant_id = $1 and id = $2")
            .bind(hc.ctx.tenant)
            .bind(retest)
            .fetch_optional(&mut **hc.tx)
            .await?;
    let (tested, result, on) = test.unwrap_or_default();
    if tested != Some(control) {
        return Err(Error::field("retest", "is a test of this finding's control"));
    }
    if result.as_deref() != Some("Effective") {
        return Err(Error::field("retest", "found the control effective"));
    }
    let raised: Option<NaiveDate> = match id(doc, "id") {
        Some(finding) => {
            sqlx::query_scalar("select (created_at at time zone $3)::date from e_finding where tenant_id = $1 and id = $2")
                .bind(hc.ctx.tenant)
                .bind(finding)
                .bind(&hc.ctx.schema.timezone)
                .fetch_optional(&mut **hc.tx)
                .await?
        }
        None => None,
    };
    if on.is_none_or(|on| on < raised.unwrap_or_else(|| hc.ctx.today())) {
        return Err(Error::field("retest", "was made after the finding was raised"));
    }
    Ok(())
}

pub struct FindingHook;

#[async_trait]
impl DocHook for FindingHook {
    fn name(&self) -> &'static str {
        "grc.finding"
    }

    fn fills(&self) -> &'static [&'static str] {
        &["overdue"]
    }

    async fn before_validate(&self, hc: &mut HookCtx<'_>, doc: &mut Doc) -> Result<()> {
        if s(doc, "status") == Some("Closed") {
            doc.insert("overdue".into(), json!(false));
        }
        // A step done is dated on the workspace's day; undone, it loses the date.
        let today = json!(hc.ctx.today().to_string());
        if let Some(Value::Array(steps)) = doc.get_mut("steps") {
            for step in steps.iter_mut().filter_map(Value::as_object_mut) {
                let done = step.get("done").and_then(Value::as_bool).unwrap_or(false);
                let dated = step.get("done_on").is_some_and(|d| !d.is_null());
                if !done {
                    step.insert("done_on".into(), Value::Null);
                } else if !dated {
                    step.insert("done_on".into(), today.clone());
                }
            }
        }
        Ok(())
    }

    async fn validate(&self, hc: &mut HookCtx<'_>, doc: &Doc) -> Result<()> {
        if s(doc, "status") != Some("Closed") {
            return Ok(());
        }
        if s(doc, "remediation").is_none() {
            return Err(Error::field("remediation", "a closed finding says how it was fixed"));
        }
        let open = rows(doc, "steps").iter().filter(|r| !b(r, "done")).count();
        if open > 0 {
            return Err(Error::field("steps", format!("{open} steps are not done")));
        }
        if b(doc, "retest_required") {
            retested(hc, doc).await?;
        }
        Ok(())
    }
}
