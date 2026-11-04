//! A security programme (FERRUM-ECOSYSTEM-014) against a real PostgreSQL
//! (`FERRUM_GRC_TEST_DATABASE_URL`, default `postgres://ferrum:ferrum@localhost:5432/ferrum_grc_test`;
//! reset first): risks scored inherent, current and residual, never worse with controls or as
//! targeted; mitigation naming its controls; a risk above the tolerance accepted only by a risk
//! approver who does not own it, until the acceptance expires; controls tested with evidence, their
//! standing going stale; policies published by revision and acknowledged again when they change;
//! findings overdue and closed saying how; and who may do what.

use chrono::{Duration, Utc};
use ferrum_kernel::secret::SecretKey;
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
    let settings = KernelSettings { secret_key: Some(SecretKey::new([7u8; 32])), ..Default::default() };
    let k = Kernel::boot(db, catalog, hooks, settings, None).await.expect("boot");
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
    ferrum_app_grc::maintenance_on(&k, today + Duration::days(91)).await.unwrap();
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
    ferrum_app_grc::maintenance_on(&k, today + Duration::days(31)).await.unwrap();
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
    ferrum_app_grc::maintenance_on(&k, today + Duration::days(10)).await.unwrap();
    assert_eq!((t.get("Finding", f1).await["overdue"].as_bool(), t.get("Finding", f2).await["overdue"].as_bool()), (Some(true), Some(false)));
    refused(t.set(&rm, "Finding", f1, json!({"status": "Closed"})).await, "invalid", "says how it was fixed");
    t.set(&rm, "Finding", f1, json!({"status": "Closed", "remediation": "Enforced for every admin"})).await.unwrap();
    assert_eq!(t.get("Finding", f1).await["overdue"], false, "closed, it is not overdue");

    // ───────────── who may do what ─────────────
    refused(t.k.insert(&ra, "Risk", obj(risk("Mine", "ra@secure.test", [1, 1, 1, 1, 1, 1], "Open", json!([])))).await, "forbidden", "");
    refused(t.k.insert(&reader, "Policy", obj(json!({"title": "Mine", "text": "x"}))).await, "forbidden", "");
    refused(t.k.insert(&ra, "ControlTest", obj(test(backups, today.to_string(), "Ineffective", json!([])))).await, "forbidden", "");
}
