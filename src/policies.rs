//! Policies. Publishing a policy whose text changed puts it at its next revision, keeping the text
//! published; what is acknowledged is a revision, once a person. A person has acknowledged a policy
//! when they acknowledged its current revision. A retired policy is no longer published.
//!
//! A policy may name an audience role: publishing a revision asks each active holder once to acknowledge it within
//! the policy's days (an attestation), withdrawing the asks of earlier revisions. Upkeep asks those who joined the
//! role since, releases those who left, reminds once before the day and marks late asks overdue.

use crate::{obj, tell};
use async_trait::async_trait;
use chrono::{Duration, NaiveDate, Utc};
use ferrum_domain::util::{elevated, id, s};
use ferrum_kernel::{Ctx, Doc, DocHook, Error, HookCtx, Kernel, Result, Tx};
use serde_json::{Value, json};
use uuid::Uuid;

pub struct PolicyHook;

#[async_trait]
impl DocHook for PolicyHook {
    fn name(&self) -> &'static str {
        "grc.policy"
    }

    async fn action(&self, hc: &mut HookCtx<'_>, name: &str, doc: &Doc, _params: &Value) -> Result<Option<Value>> {
        let policy = id(doc, "id").ok_or_else(|| Error::internal("a policy without an id"))?;
        let system = elevated(hc.ctx);
        match name {
            "publish" => {
                let revision = doc.get("revision").and_then(Value::as_i64).unwrap_or(0);
                let changed = s(doc, "text") != s(doc, "published_text");
                if !changed && s(doc, "status") == Some("Published") {
                    return Err(Error::invalid("the text is as published: there is nothing new to publish"));
                }
                let next = if changed { revision + 1 } else { revision };
                let today = hc.ctx.today();
                hc.kernel
                    .set_values_tx(
                        &system,
                        hc.tx,
                        "Policy",
                        policy,
                        obj(json!({"status": "Published", "revision": next, "published_text": s(doc, "text"), "published_on": today.to_string()})),
                    )
                    .await?;
                withdraw(hc.kernel, &system, hc.tx, policy, Some(next)).await?;
                let asked = match s(doc, "audience_role").map(str::trim).filter(|r| !r.is_empty()) {
                    Some(role) => {
                        let days = doc.get("acknowledge_within_days").and_then(Value::as_i64).unwrap_or(14);
                        ask(hc.kernel, &system, hc.tx, policy, next, s(doc, "title").unwrap_or_default(), role, today + Duration::days(days), today).await?
                    }
                    None => 0,
                };
                Ok(Some(json!({"status": "Published", "revision": next, "asked": asked})))
            }
            "acknowledge" => {
                let revision = doc.get("revision").and_then(Value::as_i64).unwrap_or(0);
                if hc.ctx.email.is_empty() {
                    return Err(Error::Forbidden("this account has no email address to record".into()));
                }
                let already = || Error::invalid(format!("you acknowledged revision {revision} already"));
                let person = hc.ctx.email.to_lowercase();
                let done: bool = sqlx::query_scalar(
                    "select exists(select 1 from e_policy_acknowledgement where tenant_id = $1 and policy = $2 and revision = $3 and lower(person) = $4)",
                )
                .bind(hc.ctx.tenant)
                .bind(policy)
                .bind(revision)
                .bind(&person)
                .fetch_one(&mut **hc.tx)
                .await?;
                if done {
                    return Err(already());
                }
                let now = Utc::now().to_rfc3339();
                hc.kernel
                    .insert_tx(
                        &system,
                        hc.tx,
                        "PolicyAcknowledgement",
                        obj(json!({"policy": policy.to_string(), "revision": revision, "person": person, "acknowledged_at": now})),
                    )
                    .await
                    .map_err(|e| if matches!(e, Error::Conflict(_)) { already() } else { e })?;
                let asked: Option<Uuid> = sqlx::query_scalar(
                    "select id from e_policy_attestation where tenant_id = $1 and policy = $2 and revision = $3 and person = $4 and status = 'Due'",
                )
                .bind(hc.ctx.tenant)
                .bind(policy)
                .bind(revision)
                .bind(&person)
                .fetch_optional(&mut **hc.tx)
                .await?;
                if let Some(a) = asked {
                    let values = obj(json!({"status": "Acknowledged", "acknowledged_at": now, "overdue": false}));
                    hc.kernel.set_values_tx(&system, hc.tx, "PolicyAttestation", a, values).await?;
                }
                Ok(Some(json!({"acknowledged": revision})))
            }
            "retire" => {
                hc.kernel.set_values_tx(&system, hc.tx, "Policy", policy, obj(json!({"status": "Retired"}))).await?;
                withdraw(hc.kernel, &system, hc.tx, policy, None).await?;
                Ok(Some(json!({"status": "Retired"})))
            }
            _ => Ok(None),
        }
    }
}

/// The policy's open asks withdrawn: all of them, or those of another revision than `keep`.
async fn withdraw(k: &Kernel, ctx: &Ctx, tx: &mut Tx, policy: Uuid, keep: Option<i64>) -> Result<()> {
    let open: Vec<Uuid> = sqlx::query_scalar(
        "select id from e_policy_attestation where tenant_id = $1 and policy = $2 and status = 'Due' and revision is distinct from $3 order by id for update",
    )
    .bind(ctx.tenant)
    .bind(policy)
    .bind(keep)
    .fetch_all(&mut **tx)
    .await?;
    for a in open {
        k.set_values_tx(ctx, tx, "PolicyAttestation", a, obj(json!({"status": "Withdrawn"}))).await?;
    }
    Ok(())
}

/// The addresses of the active people holding `role`, in lower case.
async fn holders(tx: &mut Tx, tenant: Uuid, role: &str) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "select distinct lower(u.email::text) from user_role r join app_user u on u.tenant_id = r.tenant_id and u.id = r.user_id and u.is_active \
         where r.tenant_id = $1 and r.role = $2 and (r.expires_at is null or r.expires_at > now()) and coalesce(u.email::text, '') <> '' order by 1",
    )
    .bind(tenant)
    .bind(role)
    .fetch_all(&mut **tx)
    .await?)
}

/// Each holder of `role` not yet asked for this revision asked to acknowledge it by `due`, and told. The caller holds
/// the policy's row, so nobody else asks for it meanwhile. Returns how many were asked.
#[allow(clippy::too_many_arguments)]
async fn ask(k: &Kernel, ctx: &Ctx, tx: &mut Tx, policy: Uuid, revision: i64, title: &str, role: &str, due: NaiveDate, today: NaiveDate) -> Result<i64> {
    let have: Vec<String> = sqlx::query_scalar("select person from e_policy_attestation where tenant_id = $1 and policy = $2 and revision = $3")
        .bind(ctx.tenant)
        .bind(policy)
        .bind(revision)
        .fetch_all(&mut **tx)
        .await?;
    // The ask tells the day; when that day is already inside the reminder window, no reminder repeats it.
    let days = crate::reminder_days(tx, ctx.tenant).await?;
    let reminded = (days > 0 && due - Duration::days(days) <= today).then(|| due.to_string());
    let mut asked = 0;
    for person in holders(tx, ctx.tenant, role).await?.into_iter().filter(|p| !have.contains(p)) {
        let row = k
            .insert_tx(
                ctx,
                tx,
                "PolicyAttestation",
                obj(json!({"policy": policy.to_string(), "revision": revision, "person": person, "due_on": due.to_string(), "reminded_for": reminded})),
            )
            .await?;
        let row = id(&row, "id").ok_or_else(|| Error::internal("an attestation without an id"))?;
        tell(k, ctx, tx, "grc.policy_to_acknowledge", "PolicyAttestation", row, vec![Some(person)], obj(json!({"policy": title}))).await?;
        asked += 1;
    }
    Ok(asked)
}

/// Published policies with an audience: joiners asked, leavers released; then reminders (`days` ahead, none when 0)
/// and late asks overdue. Policies and asks are held `for update`, so two upkeeps at once ask and tell once.
pub(crate) async fn upkeep(k: &Kernel, ctx: &Ctx, tx: &mut Tx, today: NaiveDate, days: i64) -> Result<()> {
    // ponytail: reads each audience role's holders every run; a change feed of role membership if a workspace has
    // thousands of policies with audiences.
    let policies: Vec<(Uuid, i64, String, String, Option<i64>)> = sqlx::query_as(
        "select id, coalesce(revision, 0)::bigint, title, trim(audience_role), acknowledge_within_days::bigint from e_policy \
         where tenant_id = $1 and status = 'Published' and coalesce(trim(audience_role), '') <> '' order by id for update",
    )
    .bind(ctx.tenant)
    .fetch_all(&mut **tx)
    .await?;
    for (policy, revision, title, role, within) in policies {
        ask(k, ctx, tx, policy, revision, &title, &role, today + Duration::days(within.unwrap_or(14)), today).await?;
        let people = holders(tx, ctx.tenant, &role).await?;
        let gone: Vec<Uuid> = sqlx::query_scalar(
            "select id from e_policy_attestation where tenant_id = $1 and policy = $2 and status = 'Due' and person <> all($3) order by id for update",
        )
        .bind(ctx.tenant)
        .bind(policy)
        .bind(&people)
        .fetch_all(&mut **tx)
        .await?;
        for a in gone {
            k.set_values_tx(ctx, tx, "PolicyAttestation", a, obj(json!({"status": "Withdrawn"}))).await?;
        }
    }
    if days > 0 {
        let soon: Vec<(Uuid, String, NaiveDate, String)> = sqlx::query_as(
            "select a.id, a.person, a.due_on, p.title from e_policy_attestation a join e_policy p on p.tenant_id = a.tenant_id and p.id = a.policy \
             where a.tenant_id = $1 and a.status = 'Due' and a.due_on >= $2 and a.due_on <= $3 and a.reminded_for is distinct from a.due_on \
             order by a.id for update of a",
        )
        .bind(ctx.tenant)
        .bind(today)
        .bind(today + Duration::days(days))
        .fetch_all(&mut **tx)
        .await?;
        for (a, person, due, title) in soon {
            tell(k, ctx, tx, "grc.policy_reminder", "PolicyAttestation", a, vec![Some(person)], obj(json!({"policy": title}))).await?;
            k.set_values_tx(ctx, tx, "PolicyAttestation", a, obj(json!({"reminded_for": due.to_string()}))).await?;
        }
    }
    let late: Vec<Uuid> = sqlx::query_scalar(
        "select id from e_policy_attestation where tenant_id = $1 and status = 'Due' and due_on < $2 and not coalesce(overdue, false) order by id for update",
    )
    .bind(ctx.tenant)
    .bind(today)
    .fetch_all(&mut **tx)
    .await?;
    for a in late {
        k.set_values_tx(ctx, tx, "PolicyAttestation", a, obj(json!({"overdue": true}))).await?;
    }
    Ok(())
}
