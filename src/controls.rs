//! Controls and their tests. A test is of a control in place, on a day not in the future, by
//! whoever records it; an effective result needs its evidence. The control's last test is its
//! latest by day; the control is effective while that test was effective and is still current.
//! Upkeep marks controls whose last test has gone stale as no longer effective. A finding left
//! open past its day is overdue; closed, it says how it was fixed.

use crate::{obj, test_every};
use async_trait::async_trait;
use chrono::{Duration, NaiveDate, Utc};
use ferrum_domain::util::{elevated, id, rows, s};
use ferrum_kernel::{Ctx, Doc, DocHook, Error, HookCtx, Kernel, Result, Tx};
use serde_json::json;
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
        if s(doc, "tested_on").is_some_and(|d| d > Utc::now().date_naive().to_string().as_str()) {
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
        standing(hc.kernel, &elevated(hc.ctx), hc.tx, control, Utc::now().date_naive()).await
    }
}

/// Every control's standing as of `today`, and findings past their day marked overdue.
pub(crate) async fn upkeep(k: &Kernel, ctx: &Ctx, tx: &mut Tx, today: NaiveDate) -> Result<()> {
    let effective: Vec<Uuid> =
        sqlx::query_scalar("select id from e_control where tenant_id = $1 and coalesce(effective, false)").bind(ctx.tenant).fetch_all(&mut **tx).await?;
    for control in effective {
        standing(k, ctx, tx, control, today).await?;
    }
    let late: Vec<Uuid> =
        sqlx::query_scalar("select id from e_finding where tenant_id = $1 and status <> 'Closed' and due_on < $2 and not coalesce(overdue, false)")
            .bind(ctx.tenant)
            .bind(today)
            .fetch_all(&mut **tx)
            .await?;
    for finding in late {
        k.set_values_tx(ctx, tx, "Finding", finding, obj(json!({"overdue": true}))).await?;
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

    async fn before_validate(&self, _hc: &mut HookCtx<'_>, doc: &mut Doc) -> Result<()> {
        if s(doc, "status") == Some("Closed") {
            doc.insert("overdue".into(), json!(false));
        }
        Ok(())
    }

    async fn validate(&self, _hc: &mut HookCtx<'_>, doc: &Doc) -> Result<()> {
        if s(doc, "status") == Some("Closed") && s(doc, "remediation").is_none() {
            return Err(Error::field("remediation", "a closed finding says how it was fixed"));
        }
        Ok(())
    }
}
