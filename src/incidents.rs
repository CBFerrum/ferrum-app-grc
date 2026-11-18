//! Incidents and the notices they owe. Who must be told, and within how many hours of detection, is a Notice Rule
//! the workspace keeps; each incident gets a notice row per rule that applies (by severity and whether personal data
//! was affected), keeps the deadlines it had and never loses a notice marked sent. Its next unsent deadline is kept
//! on the incident, and the upkeep tells the owner once when it passes. No deadline of any country is in this code.

use crate::{obj, tell};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use ferrum_domain::util::{b, id, rows, s};
use ferrum_kernel::value::parse_datetime;
use ferrum_kernel::{Ctx, Doc, DocHook, Error, HookCtx, Kernel, Result, Tx};
use serde_json::{Map, Value, json};
use uuid::Uuid;

const SEVERITY: [&str; 4] = ["Low", "Medium", "High", "Critical"];

fn rank(severity: Option<&str>) -> usize {
    severity.and_then(|v| SEVERITY.iter().position(|x| *x == v)).unwrap_or(0)
}

fn at(doc: &Doc, k: &str) -> Option<DateTime<Utc>> {
    s(doc, k).and_then(|v| parse_datetime(v).ok())
}

pub struct IncidentHook;

#[async_trait]
impl DocHook for IncidentHook {
    fn name(&self) -> &'static str {
        "grc.incident"
    }

    fn fills(&self) -> &'static [&'static str] {
        &["notices", "next_notice_due", "notice_overdue", "contained_at", "resolved_at"]
    }

    async fn before_validate(&self, hc: &mut HookCtx<'_>, doc: &mut Doc) -> Result<()> {
        let now = Utc::now();
        match s(doc, "status") {
            Some("Resolved") if at(doc, "resolved_at").is_none() => {
                doc.insert("resolved_at".into(), json!(now.to_rfc3339()));
            }
            Some("Contained") if at(doc, "contained_at").is_none() => {
                doc.insert("contained_at".into(), json!(now.to_rfc3339()));
            }
            _ => {}
        }
        let Some(detected) = at(doc, "detected_at") else { return Ok(()) };
        let rules: Vec<(Uuid, String, i64, Option<bool>, Option<String>)> = sqlx::query_as(
            "select id, recipient, hours::bigint, personal_data_only, from_severity from e_notice_rule where tenant_id = $1 and not coalesce(disabled, false) order by id",
        )
        .bind(hc.ctx.tenant)
        .fetch_all(&mut **hc.tx)
        .await?;
        let (personal, severity) = (b(doc, "personal_data_affected"), rank(s(doc, "severity")));
        let applying: Vec<&(Uuid, String, i64, Option<bool>, Option<String>)> =
            rules.iter().filter(|r| (!r.3.unwrap_or(false) || personal) && severity >= rank(r.4.as_deref())).collect();
        let mut notices: Vec<Value> = Vec::new();
        for row in rows(doc, "notices") {
            let mut row: Map<String, Value> = row.clone();
            match id(&row, "rule").and_then(|r| applying.iter().find(|a| a.0 == r)) {
                Some(rule) => {
                    row.insert("recipient".into(), json!(rule.1));
                    row.insert("due_at".into(), json!((detected + Duration::hours(rule.2)).to_rfc3339()));
                }
                // A rule that no longer applies: its notice stays once it was sent or has a reference.
                None if s(&row, "sent_at").is_none() && s(&row, "reference").is_none() => continue,
                None => {}
            }
            notices.push(Value::Object(row));
        }
        for rule in &applying {
            let had = notices.iter().any(|n| n.get("rule").and_then(Value::as_str) == Some(rule.0.to_string().as_str()));
            if !had {
                let due = (detected + Duration::hours(rule.2)).to_rfc3339();
                notices.push(json!({"id": Uuid::now_v7().to_string(), "rule": rule.0.to_string(), "recipient": rule.1, "due_at": due}));
            }
        }
        let next = notices.iter().filter_map(Value::as_object).filter(|n| s(n, "sent_at").is_none()).filter_map(|n| at(n, "due_at")).min();
        // The overdue mark is the upkeep's; it stays only while the same deadline is the next one.
        let stored: Option<(Option<DateTime<Utc>>, Option<bool>)> = match id(doc, "id") {
            Some(me) => {
                sqlx::query_as("select next_notice_due, notice_overdue from e_incident where tenant_id = $1 and id = $2")
                    .bind(hc.ctx.tenant)
                    .bind(me)
                    .fetch_optional(&mut **hc.tx)
                    .await?
            }
            None => None,
        };
        let overdue = matches!((next, stored), (Some(n), Some((Some(was), Some(true)))) if n == was);
        doc.insert("notices".into(), Value::Array(notices));
        doc.insert("next_notice_due".into(), json!(next.map(|n| n.to_rfc3339())));
        doc.insert("notice_overdue".into(), json!(overdue));
        Ok(())
    }

    async fn validate(&self, _hc: &mut HookCtx<'_>, doc: &Doc) -> Result<()> {
        let now = Utc::now();
        let Some(detected) = at(doc, "detected_at") else { return Ok(()) };
        if detected > now {
            return Err(Error::field("detected_at", "is now or before"));
        }
        let contained = at(doc, "contained_at");
        if contained.is_some_and(|c| c < detected) {
            return Err(Error::field("contained_at", "is after it was detected"));
        }
        if at(doc, "resolved_at").is_some_and(|r| r < contained.unwrap_or(detected)) {
            return Err(Error::field("resolved_at", "is after it was contained"));
        }
        if rows(doc, "notices").iter().filter_map(|n| at(n, "sent_at")).any(|t| t < detected || t > now) {
            return Err(Error::field("notices", "a notice is sent after the incident was detected, and not in the future"));
        }
        if s(doc, "status") == Some("Resolved") && s(doc, "lessons").is_none() {
            return Err(Error::field("lessons", "a resolved incident says what was learned"));
        }
        Ok(())
    }
}

/// Incidents whose next notice is past its deadline unsent: marked, and their owner told, once per deadline.
pub(crate) async fn upkeep(k: &Kernel, ctx: &Ctx, tx: &mut Tx, now: DateTime<Utc>) -> Result<()> {
    let late: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "select id, owner from e_incident where tenant_id = $1 and next_notice_due < $2 and not coalesce(notice_overdue, false) order by id for update",
    )
    .bind(ctx.tenant)
    .bind(now)
    .fetch_all(&mut **tx)
    .await?;
    for (incident, owner) in late {
        k.set_values_tx(ctx, tx, "Incident", incident, obj(json!({"notice_overdue": true}))).await?;
        tell(k, ctx, tx, "grc.incident_notice_overdue", "Incident", incident, vec![owner], Map::new()).await?;
    }
    Ok(())
}
