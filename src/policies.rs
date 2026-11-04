//! Policies. Publishing a policy whose text changed puts it at its next revision, keeping the text
//! published; what is acknowledged is a revision, once a person. A person has acknowledged a policy
//! when they acknowledged its current revision. A retired policy is no longer published.

use crate::obj;
use async_trait::async_trait;
use chrono::Utc;
use ferrum_domain::util::{elevated, id, s};
use ferrum_kernel::{Doc, DocHook, Error, HookCtx, Result};
use serde_json::{Value, json};

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
                hc.kernel
                    .set_values_tx(
                        &system,
                        hc.tx,
                        "Policy",
                        policy,
                        obj(json!({"status": "Published", "revision": next, "published_text": s(doc, "text"), "published_on": Utc::now().date_naive().to_string()})),
                    )
                    .await?;
                Ok(Some(json!({"status": "Published", "revision": next})))
            }
            "acknowledge" => {
                let revision = doc.get("revision").and_then(Value::as_i64).unwrap_or(0);
                if hc.ctx.email.is_empty() {
                    return Err(Error::Forbidden("this account has no email address to record".into()));
                }
                let done: bool = sqlx::query_scalar(
                    "select exists(select 1 from e_policy_acknowledgement where tenant_id = $1 and policy = $2 and revision = $3 and lower(person) = lower($4))",
                )
                .bind(hc.ctx.tenant)
                .bind(policy)
                .bind(revision)
                .bind(&hc.ctx.email)
                .fetch_one(&mut **hc.tx)
                .await?;
                if done {
                    return Err(Error::invalid(format!("you acknowledged revision {revision} already")));
                }
                hc.kernel
                    .insert_tx(
                        &system,
                        hc.tx,
                        "PolicyAcknowledgement",
                        obj(json!({"policy": policy.to_string(), "revision": revision, "person": hc.ctx.email.to_lowercase(), "acknowledged_at": Utc::now().to_rfc3339()})),
                    )
                    .await?;
                Ok(Some(json!({"acknowledged": revision})))
            }
            "retire" => {
                hc.kernel.set_values_tx(&system, hc.tx, "Policy", policy, obj(json!({"status": "Retired"}))).await?;
                Ok(Some(json!({"status": "Retired"})))
            }
            _ => Ok(None),
        }
    }
}
