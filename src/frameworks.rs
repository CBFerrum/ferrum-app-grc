//! Frameworks and their requirements, and the requirements a control answers. A framework's requirements form a
//! tree by reference (`parent_ref`, so a sheet can bring them in parents first); a reference is unique in its
//! framework, and a requirement a control maps or others sit under keeps its framework and reference. A control
//! maps a requirement once, never a heading, never one of a framework switched off (rows already mapped stay).
//! Frameworks come in as data: a sheet, or a library package that carries only seed records. No framework's text
//! is in this code.

use async_trait::async_trait;
use ferrum_domain::util::{id, rows, s};
use ferrum_kernel::{Doc, DocHook, Error, HookCtx, Result};
use std::collections::HashSet;
use uuid::Uuid;

pub struct RequirementHook;

#[async_trait]
impl DocHook for RequirementHook {
    fn name(&self) -> &'static str {
        "grc.requirement"
    }

    async fn validate(&self, hc: &mut HookCtx<'_>, doc: &Doc) -> Result<()> {
        let (Some(framework), Some(own)) = (id(doc, "framework"), s(doc, "ref")) else { return Ok(()) };
        let Some(parent) = s(doc, "parent_ref").map(str::trim).filter(|p| !p.is_empty()) else { return Ok(()) };
        if parent == own {
            return Err(Error::field("parent_ref", "is another requirement"));
        }
        // Walk up from the parent; reaching this requirement means it would sit under itself. The bound keeps a
        // tree two saves at once made circular finite for every reader.
        // ponytail: no lock on the tree; an advisory lock per framework if imports ever run in parallel.
        let mut at = Some(parent.to_string());
        for step in 0..50 {
            let Some(r) = at.take() else { break };
            if r == own {
                return Err(Error::field("parent_ref", "would put it under itself"));
            }
            let found: Option<Option<String>> = sqlx::query_scalar("select parent_ref from e_requirement where tenant_id = $1 and framework = $2 and ref = $3")
                .bind(hc.ctx.tenant)
                .bind(framework)
                .bind(&r)
                .fetch_optional(&mut **hc.tx)
                .await?;
            match found {
                None if step == 0 => return Err(Error::field("parent_ref", "is not a reference in this framework (bring parents in first)")),
                None => break,
                Some(up) => at = up.filter(|p| !p.trim().is_empty()),
            }
        }
        Ok(())
    }

    async fn validate_change(&self, hc: &mut HookCtx<'_>, old: Option<&Doc>, doc: &Doc) -> Result<()> {
        let Some(old) = old else { return Ok(()) };
        if id(old, "framework") == id(doc, "framework") && s(old, "ref") == s(doc, "ref") {
            return Ok(());
        }
        let (Some(me), Some(framework), Some(own)) = (id(old, "id"), id(old, "framework"), s(old, "ref")) else { return Ok(()) };
        let used: bool = sqlx::query_scalar(
            "select exists(select 1 from e_control__requirements where tenant_id = $1 and requirement = $2) \
             or exists(select 1 from e_requirement where tenant_id = $1 and framework = $3 and parent_ref = $4 and id <> $2)",
        )
        .bind(hc.ctx.tenant)
        .bind(me)
        .bind(framework)
        .bind(own)
        .fetch_one(&mut **hc.tx)
        .await?;
        if used {
            return Err(Error::invalid("a requirement in use keeps its framework and reference"));
        }
        Ok(())
    }
}

pub struct ControlHook;

#[async_trait]
impl DocHook for ControlHook {
    fn name(&self) -> &'static str {
        "grc.control"
    }

    async fn validate_change(&self, hc: &mut HookCtx<'_>, old: Option<&Doc>, doc: &Doc) -> Result<()> {
        let mapped: Vec<Uuid> = rows(doc, "requirements").iter().filter_map(|r| id(r, "requirement")).collect();
        if mapped.is_empty() {
            return Ok(());
        }
        let before: HashSet<Uuid> = old.map(|o| rows(o, "requirements").iter().filter_map(|r| id(r, "requirement")).collect()).unwrap_or_default();
        let found: Vec<(Uuid, String, Option<bool>, Option<bool>)> = sqlx::query_as(
            "select r.id, r.ref, r.assessable, f.disabled from e_requirement r join e_framework f on f.tenant_id = r.tenant_id and f.id = r.framework \
             where r.tenant_id = $1 and r.id = any($2)",
        )
        .bind(hc.ctx.tenant)
        .bind(&mapped)
        .fetch_all(&mut **hc.tx)
        .await?;
        let mut seen = HashSet::new();
        for m in &mapped {
            let Some((_, r, assessable, disabled)) = found.iter().find(|f| f.0 == *m) else { continue };
            if !seen.insert(*m) {
                return Err(Error::field("requirements", format!("{r} is listed twice")));
            }
            if before.contains(m) {
                continue;
            }
            if assessable == &Some(false) {
                return Err(Error::field("requirements", format!("{r} is a heading")));
            }
            if disabled == &Some(true) {
                return Err(Error::field("requirements", format!("{r} belongs to a framework that is switched off")));
            }
        }
        Ok(())
    }
}
