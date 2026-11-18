//! A security programme (FERRUM-ECOSYSTEM-014) against a real PostgreSQL
//! (`FERRUM_GRC_TEST_DATABASE_URL`, default `postgres://ferrum:ferrum@localhost:5432/ferrum_grc_test`;
//! reset first): risks scored inherent, current and residual, never worse with controls or as
//! targeted; mitigation naming its controls; a risk above the tolerance accepted only by a risk
//! approver who does not own it, until the acceptance expires; controls tested with evidence, their
//! standing going stale; policies published by revision and acknowledged again when they change;
//! findings overdue and closed saying how; a decided acceptance kept as decided; people told, once, before an
//! acceptance ends and a finding is due; where people's data is; and who may do what.

use chrono::{Duration, Utc};
use ferrum_kernel::tenant::NewTenant;
use ferrum_kernel::{Ctx, Db, DbConfig, Doc, Error, HookRegistry, Kernel, KernelSettings, ListQuery};
use ferrum_meta::Catalog;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

fn obj(v: Value) -> Doc {
    v.as_object().cloned().unwrap()
}

fn uid(v: &Value) -> Uuid {
    v.as_str().unwrap_or_else(|| panic!("not an id: {v}")).parse().unwrap()
}

struct T {
    k: Arc<Kernel>,
    tenant: Uuid,
    admin: Ctx,
}

impl T {
    async fn insert(&self, ctx: &Ctx, entity: &str, v: Value) -> Doc {
        self.k.insert(ctx, entity, obj(v)).await.unwrap_or_else(|e| panic!("insert {entity}: {e:?}"))
    }
    async fn get(&self, entity: &str, id: Uuid) -> Doc {
        self.k.get(&self.admin, entity, id, false).await.unwrap_or_else(|e| panic!("get {entity}: {e:?}"))
    }
    async fn user(&self, email: &str, roles: &[&str]) -> Ctx {
        let roles: Vec<String> = roles.iter().map(|r| r.to_string()).collect();
        let id = self.k.create_user(&self.admin, email, email, Some("Correct-Horse-9"), &roles, false).await.expect("user");
        let s = self.k.login("secure", email, "Correct-Horse-9").await.expect("login");
        self.k.load_ctx(self.tenant, id, Some(s.token_version), "it".into()).await.expect("ctx")
    }
    async fn act(&self, ctx: &Ctx, entity: &str, id: Uuid, action: &str) -> Result<Value, Error> {
        self.k.run_action(ctx, entity, id, action, Value::Null).await
    }
    async fn set(&self, ctx: &Ctx, entity: &str, id: Uuid, v: Value) -> Result<Doc, Error> {
        self.k.update(ctx, entity, id, obj(v), None).await
    }
}

fn refused<V: std::fmt::Debug>(r: Result<V, Error>, kind: &str, says: &str) {
    let msg = format!("{r:?}");
    let ok = matches!(
        (&r, kind),
        (Err(Error::Invalid(_) | Error::Validation(_)), "invalid") | (Err(Error::Forbidden(_)), "forbidden") | (Err(Error::NotFound(_)), "not found")
    );
    assert!(ok && msg.contains(says), "expected {kind} saying {says:?}, got {msg}");
}

#[test]
fn a_security_programme() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().thread_stack_size(16 << 20).build().unwrap();
    rt.block_on(async { tokio::spawn(scenario()).await.unwrap() });
}

async fn scenario() {
    let url = std::env::var("FERRUM_GRC_TEST_DATABASE_URL").unwrap_or_else(|_| "postgres://ferrum:ferrum@localhost:5432/ferrum_grc_test".into());
    let db = Db::connect(DbConfig { url, max_connections: 16, ..Default::default() }).await.expect("connect");
    sqlx::raw_sql("drop schema if exists public cascade; create schema public;").execute(&db.pool).await.expect("reset");
    let mut packages = ferrum_domain::packages().expect("platform packages");
    packages.extend(ferrum_app_grc::packages().expect("app packages"));
    let catalog = Catalog::from_packages(packages).expect("catalog");
    let mut hooks = HookRegistry::default();
    ferrum_domain::register(&mut hooks);
    ferrum_app_grc::register(&mut hooks);
    let k = Kernel::boot(db, catalog, hooks, KernelSettings::default(), None).await.expect("boot");
    ferrum_domain::maintenance(&k).await.expect("partitions");
    let tenant = k
        .create_tenant(NewTenant {
            slug: "secure".into(),
            name: "Secure Co".into(),
            admin_email: "admin@secure.test".into(),
            admin_password: "Correct-Horse-9".into(),
            admin_name: None,
            packages: vec!["grc".into()],
            settings: Some(json!({"timezone": "UTC"})),
        })
        .await
        .expect("tenant");
    let session = k.login("secure", "admin@secure.test", "Correct-Horse-9").await.expect("login");
    let admin = k.load_ctx(tenant, session.user, Some(session.token_version), "it".into()).await.expect("ctx");
    let t = T { k: k.clone(), tenant, admin };
    let rm = t.user("rm@secure.test", &["Risk Manager"]).await;
    let ra = t.user("ra@secure.test", &["Risk Approver"]).await;
    let owner_approver = t.user("cfo@secure.test", &["Risk Approver"]).await;
    let reader = t.user("pat@secure.test", &["Policy Reader"]).await;
    let reader2 = t.user("quinn@secure.test", &["Policy Reader"]).await;
    let today = Utc::now().date_naive();
    t.insert(&rm, "GrcSettings", json!({"tolerance": 6, "test_every_days": 90})).await;

    // ───────────── controls and their tests ─────────────
    let mfa = uid(&t
        .insert(&rm, "Control", json!({"control_name": "Multi-factor sign-in", "category": "Technical", "status": "Planned", "references": "A.8.5"}))
        .await["id"]);
    let backups = uid(&t.insert(&rm, "Control", json!({"control_name": "Nightly backups", "category": "Technical", "status": "In Place"})).await["id"]);
    let test = |control: Uuid, on: String, result: &str, evidence: Value| json!({"control": control.to_string(), "tested_on": on, "result": result, "evidence": evidence});
    let proof = json!([{"title": "Restore log", "file": "/files/restore-log"}]);
    refused(t.k.insert(&rm, "ControlTest", obj(test(mfa, today.to_string(), "Effective", proof.clone()))).await, "invalid", "once it is in place");
    refused(
        t.k.insert(&rm, "ControlTest", obj(test(backups, today.to_string(), "Effective", json!([{"title": "Said so"}])))).await,
        "invalid",
        "has its evidence",
    );
    refused(
        t.k.insert(&rm, "ControlTest", obj(test(backups, (today + Duration::days(1)).to_string(), "Effective", proof.clone()))).await,
        "invalid",
        "today or before",
    );
    let old = t.insert(&rm, "ControlTest", test(backups, (today - Duration::days(30)).to_string(), "Ineffective", json!([]))).await;
    assert_eq!(old["tester"], "rm@secure.test");
    assert_eq!(
        (t.get("Control", backups).await["effective"].as_bool(), t.get("Control", backups).await["last_result"].as_str()),
        (Some(false), Some("Ineffective"))
    );
    t.insert(&rm, "ControlTest", test(backups, today.to_string(), "Effective", proof.clone())).await;
    let c = t.get("Control", backups).await;
    assert_eq!((c["effective"].as_bool(), c["last_tested_on"].as_str()), (Some(true), Some(today.to_string().as_str())));
    // An older test entered later is not the last one.
    t.insert(&rm, "ControlTest", test(backups, (today - Duration::days(10)).to_string(), "Ineffective", json!([]))).await;
    assert_eq!(t.get("Control", backups).await["effective"], true, "the latest by day stands");
    ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(91)).await.unwrap();
    assert_eq!(t.get("Control", backups).await["effective"], false, "a test 91 days old is stale");
    t.insert(&rm, "ControlTest", test(backups, today.to_string(), "Effective", proof.clone())).await;
    t.set(&rm, "Control", mfa, json!({"status": "In Place"})).await.unwrap();

    // ───────────── risks ─────────────
    let risk = |title: &str, owner: &str, scores: [i64; 6], treatment: &str, controls: Value| {
        json!({"title": title, "owner": owner, "inherent_likelihood": scores[0], "inherent_impact": scores[1], "current_likelihood": scores[2], "current_impact": scores[3],
               "residual_likelihood": scores[4], "residual_impact": scores[5], "treatment": treatment, "controls": controls})
    };
    refused(t.k.insert(&rm, "Risk", obj(risk("Bad", "cfo@secure.test", [6, 3, 3, 3, 2, 2], "Open", json!([])))).await, "invalid", "from 1 to 5");
    refused(t.k.insert(&rm, "Risk", obj(risk("Worse", "cfo@secure.test", [2, 2, 3, 3, 2, 2], "Open", json!([])))).await, "invalid", "do not make a risk worse");
    refused(
        t.k.insert(&rm, "Risk", obj(risk("Target", "cfo@secure.test", [4, 4, 3, 3, 4, 4], "Open", json!([])))).await,
        "invalid",
        "no worse than the risk now",
    );
    refused(t.k.insert(&rm, "Risk", obj(risk("Bare", "cfo@secure.test", [4, 4, 3, 3, 2, 2], "Mitigate", json!([])))).await, "invalid", "names the controls");
    let ransom = t
        .insert(
            &rm,
            "Risk",
            risk("Ransomware", "cfo@secure.test", [5, 5, 4, 4, 2, 3], "Mitigate", json!([{"control": backups.to_string()}, {"control": mfa.to_string()}])),
        )
        .await;
    assert_eq!(
        (ransom["inherent_score"].as_i64(), ransom["current_score"].as_i64(), ransom["residual_score"].as_i64(), ransom["level"].as_str()),
        (Some(25), Some(16), Some(6), Some("High"))
    );
    let ransom_id = uid(&ransom["id"]);
    let small = uid(&t.insert(&rm, "Risk", risk("Printer jams", "cfo@secure.test", [2, 3, 2, 3, 1, 1], "Accept", json!([]))).await["id"]);
    assert_eq!(t.get("Risk", small).await["level"], "Medium", "6, at the tolerance: accepted without an acceptance");
    refused(t.set(&rm, "Risk", ransom_id, json!({"treatment": "Accept"})).await, "invalid", "only with an approved acceptance");

    // ───────────── accepting a risk ─────────────
    let acceptance = |risk: Uuid, until: String| json!({"risk": risk.to_string(), "justification": "Insurance covers it this year", "expires_on": until});
    refused(t.k.insert(&rm, "RiskAcceptance", obj(acceptance(ransom_id, today.to_string()))).await, "invalid", "is after today");
    let acc = uid(&t.insert(&rm, "RiskAcceptance", acceptance(ransom_id, (today + Duration::days(30)).to_string())).await["id"]);
    refused(t.act(&rm, "RiskAcceptance", acc, "accept_risk").await, "forbidden", "a Risk Approver decides");
    refused(t.act(&owner_approver, "RiskAcceptance", acc, "accept_risk").await, "forbidden", "owner does not approve");
    t.act(&ra, "RiskAcceptance", acc, "accept_risk").await.expect("accepted");
    let r = t.get("Risk", ransom_id).await;
    assert_eq!(r["treatment"], "Accept");
    t.set(&rm, "Risk", ransom_id, json!({"description": "Encrypted shares"})).await.expect("an accepted risk is kept");
    ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(31)).await.unwrap();
    assert_eq!(t.get("RiskAcceptance", acc).await["status"], "Expired");
    assert_eq!(t.get("Risk", ransom_id).await["treatment"], "Open", "open again once its acceptance expired");
    let again = uid(&t.insert(&rm, "RiskAcceptance", acceptance(ransom_id, (today + Duration::days(60)).to_string())).await["id"]);
    t.act(&ra, "RiskAcceptance", again, "accept_risk").await.unwrap();
    refused(t.act(&rm, "RiskAcceptance", again, "revoke_acceptance").await, "forbidden", "a Risk Approver revokes");
    // Past its day before upkeep has run, an acceptance no longer holds a risk.
    let mut tx = t.k.db.tenant_tx(t.tenant).await.unwrap();
    sqlx::query("update e_risk_acceptance set expires_on = $2 where tenant_id = $1 and id = $3")
        .bind(t.tenant)
        .bind(today - Duration::days(1))
        .bind(again)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    t.set(&rm, "Risk", ransom_id, json!({"treatment": "Open"})).await.unwrap();
    refused(t.set(&rm, "Risk", ransom_id, json!({"treatment": "Accept"})).await, "invalid", "only with an approved acceptance");
    let mut tx = t.k.db.tenant_tx(t.tenant).await.unwrap();
    sqlx::query("update e_risk_acceptance set expires_on = $2 where tenant_id = $1 and id = $3")
        .bind(t.tenant)
        .bind(today + Duration::days(60))
        .bind(again)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    t.set(&rm, "Risk", ransom_id, json!({"treatment": "Accept"})).await.expect("held again once its day is ahead");
    t.act(&ra, "RiskAcceptance", again, "revoke_acceptance").await.expect("revoked");
    assert_eq!(t.get("Risk", ransom_id).await["treatment"], "Open", "open again once revoked");
    let no = uid(&t.insert(&rm, "RiskAcceptance", acceptance(ransom_id, (today + Duration::days(60)).to_string())).await["id"]);
    t.act(&ra, "RiskAcceptance", no, "reject_acceptance").await.unwrap();
    assert_eq!((t.get("RiskAcceptance", no).await["status"].as_str(), t.get("Risk", ransom_id).await["treatment"].as_str()), (Some("Rejected"), Some("Open")));

    // ───────────── a decided acceptance keeps its day, its reason and its risk ─────────────
    let outage = uid(&t
        .insert(&rm, "Risk", risk("Supplier outage", "cfo@secure.test", [4, 4, 4, 4, 2, 2], "Open", json!([{"control": backups.to_string()}])))
        .await["id"]);
    let held = uid(&t.insert(&rm, "RiskAcceptance", acceptance(outage, (today + Duration::days(20)).to_string())).await["id"]);
    // A draft acceptance can still be changed.
    t.set(&rm, "RiskAcceptance", held, json!({"justification": "Two suppliers by spring", "expires_on": (today + Duration::days(21)).to_string()}))
        .await
        .expect("a draft is the proposer's to change");
    t.set(&rm, "RiskAcceptance", held, json!({"expires_on": (today + Duration::days(20)).to_string()})).await.unwrap();
    t.act(&ra, "RiskAcceptance", held, "accept_risk").await.expect("accepted");
    let ten_years = (today + Duration::days(3650)).to_string();
    for who in [&rm, &ra, &t.admin] {
        refused(t.set(who, "RiskAcceptance", held, json!({"expires_on": ten_years})).await, "invalid", "keeps its risk");
        refused(t.set(who, "RiskAcceptance", held, json!({"justification": "Something else"})).await, "invalid", "keeps its risk");
        refused(t.set(who, "RiskAcceptance", held, json!({"risk": small.to_string()})).await, "invalid", "keeps its risk");
    }
    let kept = t.get("RiskAcceptance", held).await;
    assert_eq!(
        (kept["expires_on"].as_str(), kept["justification"].as_str(), kept["risk"].as_str()),
        (Some((today + Duration::days(20)).to_string().as_str()), Some("Two suppliers by spring"), Some(outage.to_string().as_str()))
    );

    // ───────────── an acceptance whose day has passed is not accepted ─────────────
    let late = uid(&t.insert(&rm, "RiskAcceptance", acceptance(outage, (today + Duration::days(5)).to_string())).await["id"]);
    let mut tx = t.k.db.tenant_tx(t.tenant).await.unwrap();
    sqlx::query("update e_risk_acceptance set expires_on = $2 where tenant_id = $1 and id = $3")
        .bind(t.tenant)
        .bind(today - Duration::days(1))
        .bind(late)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    refused(t.act(&ra, "RiskAcceptance", late, "accept_risk").await, "invalid", "expires_on");
    assert_eq!(t.get("RiskAcceptance", late).await["status"], "Draft");

    // ───────────── people are told before an acceptance ends and when it ends ─────────────
    let sends = |record: Uuid, template: &'static str| {
        let k = k.clone();
        async move {
            let mut tx = k.db.tenant_tx(tenant).await.unwrap();
            let n: i64 = sqlx::query_scalar("select count(*) from message_send where tenant_id = $1 and record_id = $2 and template = $3")
                .bind(tenant)
                .bind(record)
                .bind(template)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            n
        }
    };
    let settings = uid(&t.k.list(&rm, "GrcSettings", &ListQuery::default()).await.unwrap().rows[0]["id"]);
    t.set(&rm, "GrcSettings", settings, json!({"reminder_days": 14})).await.unwrap();
    ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(5)).await.unwrap();
    assert_eq!(sends(held, "grc.acceptance_expiring").await, 0, "15 days ahead: not yet");
    // Two upkeeps at once tell once.
    let (a, b) = tokio::join!(
        ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(10)),
        ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(10))
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(sends(held, "grc.acceptance_expiring").await, 2, "the risk's owner and the approver, once each");
    ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(11)).await.unwrap();
    assert_eq!(sends(held, "grc.acceptance_expiring").await, 2, "not again");
    assert_eq!(sends(held, "grc.acceptance_expired").await, 0);

    // ───────────── expiry leaves a treatment someone chose ─────────────
    assert_eq!(t.get("Risk", outage).await["treatment"], "Accept");
    t.set(&rm, "Risk", outage, json!({"treatment": "Mitigate"})).await.expect("mitigated after all");
    ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(21)).await.unwrap();
    assert_eq!(t.get("RiskAcceptance", held).await["status"], "Expired");
    assert_eq!(t.get("Risk", outage).await["treatment"], "Mitigate", "an expiry does not undo a treatment chosen since");
    assert_eq!(sends(held, "grc.acceptance_expired").await, 2, "the risk's owner and the approver, told it ended");
    ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(22)).await.unwrap();
    assert_eq!(sends(held, "grc.acceptance_expired").await, 2, "once");

    // ───────────── policies ─────────────
    let policy = uid(&t.insert(&rm, "Policy", json!({"title": "Acceptable use", "owner": "rm@secure.test", "text": "Lock your screen."})).await["id"]);
    refused(t.k.get(&reader, "Policy", policy, false).await, "not found", "");
    t.act(&rm, "Policy", policy, "publish").await.expect("published");
    let p = t.get("Policy", policy).await;
    assert_eq!((p["revision"].as_i64(), p["published_text"].as_str()), (Some(1), Some("Lock your screen.")));
    refused(t.act(&rm, "Policy", policy, "publish").await, "invalid", "nothing new to publish");
    t.act(&reader, "Policy", policy, "acknowledge").await.expect("read it");
    refused(t.act(&reader, "Policy", policy, "acknowledge").await, "invalid", "acknowledged revision 1 already");
    t.set(&rm, "Policy", policy, json!({"text": "Lock your screen. Report lost devices."})).await.unwrap();
    assert_eq!(t.get("Policy", policy).await["published_text"], "Lock your screen.", "what was published stays until published again");
    t.act(&rm, "Policy", policy, "publish").await.unwrap();
    assert_eq!(t.get("Policy", policy).await["revision"], 2);
    t.act(&reader, "Policy", policy, "acknowledge").await.expect("revision 2 is new to her");
    t.act(&reader2, "Policy", policy, "acknowledge").await.unwrap();
    let acks = t.k.list(&t.admin, "PolicyAcknowledgement", &ListQuery::default()).await.unwrap().rows;
    let mut seen: Vec<(String, i64)> = acks.iter().map(|a| (a["person"].as_str().unwrap().to_string(), a["revision"].as_i64().unwrap())).collect();
    seen.sort();
    assert_eq!(seen, [("pat@secure.test".to_string(), 1), ("pat@secure.test".to_string(), 2), ("quinn@secure.test".to_string(), 2)]);
    let hers = t.k.list(&reader2, "PolicyAcknowledgement", &ListQuery::default()).await.unwrap().rows;
    assert_eq!(hers.len(), 1, "a reader sees her own acknowledgements");
    t.act(&rm, "Policy", policy, "retire").await.unwrap();
    refused(t.act(&reader, "Policy", policy, "acknowledge").await, "not found", "");

    // ───────────── findings ─────────────
    let finding = |title: &str, due: String| json!({"title": title, "severity": "High", "control": mfa.to_string(), "owner": "rm@secure.test", "due_on": due});
    let f1 = uid(&t.insert(&rm, "Finding", finding("MFA not on admin accounts", (today + Duration::days(7)).to_string())).await["id"]);
    let f2 = uid(&t.insert(&rm, "Finding", finding("Old VPN accounts", (today + Duration::days(30)).to_string())).await["id"]);
    let mut done = finding("Shared admin password", (today + Duration::days(3)).to_string());
    done["status"] = json!("Closed");
    done["remediation"] = json!("Rotated and vaulted");
    let f3 = uid(&t.insert(&rm, "Finding", done).await["id"]);
    // A finding's owner is told before it is due and when it is overdue, each once; closed findings never.
    ferrum_app_grc::maintenance_on(&k, tenant, today).await.unwrap();
    ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(1)).await.unwrap();
    assert_eq!((sends(f1, "grc.finding_due").await, sends(f2, "grc.finding_due").await), (1, 0), "due within 14 days, once");
    ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(10)).await.unwrap();
    assert_eq!((t.get("Finding", f1).await["overdue"].as_bool(), t.get("Finding", f2).await["overdue"].as_bool()), (Some(true), Some(false)));
    ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(11)).await.unwrap();
    assert_eq!((sends(f1, "grc.finding_overdue").await, sends(f1, "grc.finding_due").await), (1, 1), "overdue, once");
    assert_eq!((sends(f3, "grc.finding_due").await, sends(f3, "grc.finding_overdue").await), (0, 0), "a closed finding is nobody's errand");
    // Reminder days of zero tell nobody.
    t.set(&rm, "GrcSettings", settings, json!({"reminder_days": 0})).await.unwrap();
    let quiet = uid(&t.insert(&rm, "Finding", finding("Unsigned NDAs", (today + Duration::days(13)).to_string())).await["id"]);
    let quiet_acc = uid(&t.insert(&rm, "RiskAcceptance", acceptance(outage, (today + Duration::days(13)).to_string())).await["id"]);
    t.act(&ra, "RiskAcceptance", quiet_acc, "accept_risk").await.unwrap();
    ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(11)).await.unwrap();
    assert_eq!((sends(quiet, "grc.finding_due").await, sends(quiet_acc, "grc.acceptance_expiring").await), (0, 0), "no reminders");
    t.set(&rm, "GrcSettings", settings, json!({"reminder_days": 14})).await.unwrap();
    refused(t.set(&rm, "Finding", f1, json!({"status": "Closed"})).await, "invalid", "says how it was fixed");
    t.set(&rm, "Finding", f1, json!({"status": "Closed", "remediation": "Enforced for every admin"})).await.unwrap();
    assert_eq!(t.get("Finding", f1).await["overdue"], false, "closed, it is not overdue");

    // ───────────── who may do what ─────────────
    refused(t.k.insert(&ra, "Risk", obj(risk("Mine", "ra@secure.test", [1, 1, 1, 1, 1, 1], "Open", json!([])))).await, "forbidden", "");
    refused(t.k.insert(&reader, "Policy", obj(json!({"title": "Mine", "text": "x"}))).await, "forbidden", "");
    refused(t.k.insert(&ra, "ControlTest", obj(test(backups, today.to_string(), "Ineffective", json!([])))).await, "forbidden", "");

    // ───────────── the package says where people's data is, and what each action promises ─────────────
    let grc = ferrum_app_grc::packages().unwrap().into_iter().find(|p| p.name() == "grc").unwrap();
    let mut declared: Vec<&str> = grc.manifest.personal_data.iter().map(|d| d.entity.as_str()).collect();
    declared.sort();
    assert_eq!(declared, ["Control", "ControlTest", "Finding", "Policy", "PolicyAcknowledgement", "Risk", "RiskAcceptance"]);
    let mut handed: Vec<&str> = grc.manifest.handover.iter().map(|h| h.entity.as_str()).collect();
    handed.sort();
    assert_eq!(handed, ["Control", "Finding", "Policy", "Risk"]);
    let theirs = t.k.personal_data(&t.admin, "rm@secure.test").await.expect("their data").to_string();
    for f in [f1, f2, f3, quiet] {
        assert!(theirs.contains(&f.to_string()), "the findings rm owns are hers: {f}");
    }
    let actions: Vec<_> = grc.entities.iter().flat_map(|e| e.actions.iter()).collect();
    assert_eq!(actions.len(), 6);
    for a in actions {
        assert!(a.contract.as_ref().and_then(|c| c.completion.as_deref()).is_some_and(|c| !c.is_empty()), "{} says what done means", a.name);
    }

    // ───────────── the workspace's day, not UTC's ─────────────
    // No clock can be set: as the platform's own suites do, the workspace moves to a zone whose day is not UTC's now
    // (UTC-11 before 10:00 UTC, UTC+14 after), and what the app dates or checks against "today" is the workspace's day.
    let zone = if chrono::Timelike::hour(&Utc::now()) < 10 { "Pacific/Pago_Pago" } else { "Pacific/Kiritimati" };
    t.k.update_tenant_settings(&t.admin, &obj(json!({"timezone": zone}))).await.expect("the workspace's zone");
    let again = |who: &Ctx| t.k.load_ctx(t.tenant, who.user, None, "it".into());
    let (rm, ra) = (again(&rm).await.unwrap(), again(&ra).await.unwrap());
    let day = rm.today();
    assert_ne!(day, Utc::now().date_naive(), "{zone}'s day is not UTC's");
    let rules = uid(&t.insert(&rm, "Policy", json!({"title": "Clean desk", "owner": "rm@secure.test", "text": "Clear your desk."})).await["id"]);
    t.act(&rm, "Policy", rules, "publish").await.unwrap();
    assert_eq!(t.get("Policy", rules).await["published_on"], json!(day.to_string()), "published on the workspace's day");
    let taken = uid(&t.insert(&rm, "RiskAcceptance", acceptance(ransom_id, (day + Duration::days(30)).to_string())).await["id"]);
    t.act(&ra, "RiskAcceptance", taken, "accept_risk").await.unwrap();
    assert_eq!(t.get("RiskAcceptance", taken).await["decided_on"], json!(day.to_string()), "decided on the workspace's day");
    let on_day = t.k.insert(&rm, "ControlTest", obj(test(backups, day.to_string(), "Effective", proof.clone()))).await;
    assert!(on_day.is_ok(), "a test on the workspace's day ({day}): {:?}", on_day.err());
    refused(t.k.insert(&rm, "ControlTest", obj(test(backups, (day + Duration::days(1)).to_string(), "Effective", proof))).await, "invalid", "today or before");
}
