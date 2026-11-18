//! Risks and their acceptance. A risk is scored three times on a five-by-five matrix: before
//! controls (inherent), with them (current), and as targeted (residual); controls never make it
//! worse, nor does the target. Its level is the current score's. Mitigating means naming the
//! controls; accepting a risk above the tolerance means an acceptance approved by a risk approver
//! who does not own it, until it expires, when the risk is open again (CISO Assistant's risk
//! scenarios and acceptances).

use crate::{obj, tell, tolerance};
use async_trait::async_trait;
use chrono::NaiveDate;
use ferrum_domain::util::{elevated, id, rows, s};
use ferrum_kernel::{Ctx, Doc, DocHook, Error, HookCtx, Kernel, Result, Tx};
use serde_json::{Value, json};
use uuid::Uuid;

/// The level of a score out of 25.
pub(crate) fn level(score: i64) -> &'static str {
    match score {
        ..=4 => "Low",
        5..=9 => "Medium",
        10..=16 => "High",
        _ => "Critical",
    }
}

fn n(doc: &Doc, k: &str) -> i64 {
    doc.get(k).and_then(Value::as_i64).unwrap_or(0)
}

pub struct RiskHook;

#[async_trait]
impl DocHook for RiskHook {
    fn name(&self) -> &'static str {
        "grc.risk"
    }

    fn fills(&self) -> &'static [&'static str] {
        &["inherent_score", "current_score", "residual_score", "level"]
    }

    async fn before_validate(&self, _hc: &mut HookCtx<'_>, doc: &mut Doc) -> Result<()> {
        let score = |l: &str, i: &str| n(doc, l) * n(doc, i);
        let (inherent, current, residual) =
            (score("inherent_likelihood", "inherent_impact"), score("current_likelihood", "current_impact"), score("residual_likelihood", "residual_impact"));
        doc.insert("inherent_score".into(), json!(inherent));
        doc.insert("current_score".into(), json!(current));
        doc.insert("residual_score".into(), json!(residual));
        doc.insert("level".into(), json!(level(current)));
        Ok(())
    }

    async fn validate(&self, hc: &mut HookCtx<'_>, doc: &Doc) -> Result<()> {
        for k in ["inherent_likelihood", "inherent_impact", "current_likelihood", "current_impact", "residual_likelihood", "residual_impact"] {
            if !(1..=5).contains(&n(doc, k)) {
                return Err(Error::field(k, "is from 1 to 5"));
            }
        }
        if n(doc, "current_score") > n(doc, "inherent_score") {
            return Err(Error::field("current_likelihood", "controls do not make a risk worse than it is without them"));
        }
        if n(doc, "residual_score") > n(doc, "current_score") {
            return Err(Error::field("residual_likelihood", "the target is no worse than the risk now"));
        }
        match s(doc, "treatment") {
            Some("Mitigate") if rows(doc, "controls").is_empty() => return Err(Error::field("controls", "mitigating names the controls that do it")),
            Some("Accept")
                if n(doc, "current_score") > tolerance(hc.tx, hc.ctx.tenant).await? && !accepted(hc.tx, hc.ctx, id(doc, "id"), hc.ctx.today()).await? =>
            {
                return Err(Error::field("treatment", "a risk above the tolerance is accepted only with an approved acceptance"));
            }
            _ => {}
        }
        Ok(())
    }
}

/// Whether `risk` has an acceptance approved and not yet expired on `day`.
async fn accepted(tx: &mut Tx, ctx: &Ctx, risk: Option<Uuid>, day: NaiveDate) -> Result<bool> {
    let Some(risk) = risk else { return Ok(false) };
    Ok(sqlx::query_scalar("select exists(select 1 from e_risk_acceptance where tenant_id = $1 and risk = $2 and status = 'Accepted' and expires_on >= $3)")
        .bind(ctx.tenant)
        .bind(risk)
        .bind(day)
        .fetch_one(&mut **tx)
        .await?)
}

pub struct AcceptanceHook;

#[async_trait]
impl DocHook for AcceptanceHook {
    fn name(&self) -> &'static str {
        "grc.acceptance"
    }

    async fn validate(&self, hc: &mut HookCtx<'_>, doc: &Doc) -> Result<()> {
        if s(doc, "status") == Some("Draft") && s(doc, "expires_on").is_some_and(|e| e <= hc.ctx.today().to_string().as_str()) {
            return Err(Error::field("expires_on", "is after today"));
        }
        Ok(())
    }

    /// What an approver decided on is what stands: once decided, an acceptance keeps its risk, its reason and its
    /// day, whoever edits it. Only the app's own writes (status, approver, day decided) go through.
    async fn validate_change(&self, hc: &mut HookCtx<'_>, old: Option<&Doc>, doc: &Doc) -> Result<()> {
        let Some(old) = old else { return Ok(()) };
        if hc.ctx.is_system || matches!(s(old, "status"), None | Some("Draft")) {
            return Ok(());
        }
        if ["risk", "justification", "expires_on"].iter().any(|f| old.get(*f) != doc.get(*f)) {
            return Err(Error::invalid("a decided acceptance keeps its risk, its reason and its day: propose a new one"));
        }
        Ok(())
    }

    async fn action(&self, hc: &mut HookCtx<'_>, name: &str, doc: &Doc, _params: &Value) -> Result<Option<Value>> {
        let acceptance = id(doc, "id").ok_or_else(|| Error::internal("an acceptance without an id"))?;
        let risk_id = id(doc, "risk").ok_or_else(|| Error::field("risk", "is required"))?;
        let system = elevated(hc.ctx);
        let approver = hc.ctx.is_admin || hc.ctx.roles.iter().any(|r| r == "Risk Approver");
        let today = hc.ctx.today().to_string();
        let values = match name {
            "accept_risk" | "reject_acceptance" => {
                if !approver {
                    return Err(Error::Forbidden("a Risk Approver decides an acceptance".into()));
                }
                let risk = hc.kernel.get_tx(&system, hc.tx, "Risk", risk_id, false).await?;
                if s(&risk, "owner").is_some_and(|o| o.eq_ignore_ascii_case(&hc.ctx.email)) {
                    return Err(Error::Forbidden("a risk's owner does not approve taking it on".into()));
                }
                if name == "accept_risk" && s(doc, "expires_on").is_some_and(|e| e <= today.as_str()) {
                    return Err(Error::field("expires_on", "has passed: propose it again with a later day"));
                }
                let to = if name == "accept_risk" { "Accepted" } else { "Rejected" };
                json!({"status": to, "approver": hc.ctx.email, "decided_on": today})
            }
            "revoke_acceptance" => {
                if !approver {
                    return Err(Error::Forbidden("a Risk Approver revokes an acceptance".into()));
                }
                json!({"status": "Revoked", "decided_on": today})
            }
            _ => return Ok(None),
        };
        let status = values["status"].clone();
        hc.kernel.set_values_tx(&system, hc.tx, "RiskAcceptance", acceptance, obj(values)).await?;
        if status == "Accepted" {
            hc.kernel.set_values_tx(&system, hc.tx, "Risk", risk_id, obj(json!({"treatment": "Accept"}))).await?;
        } else if status == "Revoked" {
            reopen(hc.kernel, &system, hc.tx, risk_id, hc.ctx.today()).await?;
        }
        Ok(Some(json!({"status": status})))
    }
}

/// A risk whose acceptance ended on `day`, open again unless another acceptance still holds it or it is treated
/// another way by now.
async fn reopen(k: &Kernel, ctx: &Ctx, tx: &mut Tx, risk: Uuid, day: NaiveDate) -> Result<()> {
    if !accepted(tx, ctx, Some(risk), day).await? {
        let treatment: Option<String> = sqlx::query_scalar("select treatment from e_risk where tenant_id = $1 and id = $2")
            .bind(ctx.tenant)
            .bind(risk)
            .fetch_optional(&mut **tx)
            .await?
            .flatten();
        if treatment.as_deref() == Some("Accept") {
            k.set_values_tx(ctx, tx, "Risk", risk, obj(json!({"treatment": "Open"}))).await?;
        }
    }
    Ok(())
}

/// Acceptances past their day, expired, their risks open again unless treated another way meanwhile, and the risk's
/// owner and the approver told. Rows are held, so two upkeeps at once expire and tell once.
pub(crate) async fn expire(k: &Kernel, ctx: &Ctx, tx: &mut Tx, today: NaiveDate) -> Result<()> {
    let due: Vec<(Uuid, Uuid, Option<String>)> = sqlx::query_as(
        "select id, risk, approver from e_risk_acceptance where tenant_id = $1 and status = 'Accepted' and expires_on < $2 order by id for update",
    )
    .bind(ctx.tenant)
    .bind(today)
    .fetch_all(&mut **tx)
    .await?;
    for (acceptance, risk, approver) in due {
        k.set_values_tx(ctx, tx, "RiskAcceptance", acceptance, obj(json!({"status": "Expired"}))).await?;
        reopen(k, ctx, tx, risk, today).await?;
        tell_about(k, ctx, tx, "grc.acceptance_expired", acceptance, risk, approver).await?;
    }
    Ok(())
}

/// Accepted acceptances ending within `days`, their risk's owner and the approver told once for the day they end.
pub(crate) async fn remind(k: &Kernel, ctx: &Ctx, tx: &mut Tx, today: NaiveDate, days: i64) -> Result<()> {
    let ending: Vec<(Uuid, Uuid, Option<String>, NaiveDate)> = sqlx::query_as(
        "select id, risk, approver, expires_on from e_risk_acceptance where tenant_id = $1 and status = 'Accepted' \
         and expires_on >= $2 and expires_on <= $3 and reminded_for is distinct from expires_on order by id for update",
    )
    .bind(ctx.tenant)
    .bind(today)
    .bind(today + chrono::Duration::days(days))
    .fetch_all(&mut **tx)
    .await?;
    for (acceptance, risk, approver, ends) in ending {
        tell_about(k, ctx, tx, "grc.acceptance_expiring", acceptance, risk, approver).await?;
        k.set_values_tx(ctx, tx, "RiskAcceptance", acceptance, obj(json!({"reminded_for": ends.to_string()}))).await?;
    }
    Ok(())
}

/// An acceptance's message to its risk's owner and its approver, naming the risk.
async fn tell_about(k: &Kernel, ctx: &Ctx, tx: &mut Tx, template: &str, acceptance: Uuid, risk: Uuid, approver: Option<String>) -> Result<()> {
    let (owner, title): (Option<String>, Option<String>) = sqlx::query_as("select owner, title from e_risk where tenant_id = $1 and id = $2")
        .bind(ctx.tenant)
        .bind(risk)
        .fetch_optional(&mut **tx)
        .await?
        .unwrap_or_default();
    tell(k, ctx, tx, template, "RiskAcceptance", acceptance, vec![owner, approver], obj(json!({"risk": title}))).await
}
