//! A security programme (FERRUM-ECOSYSTEM-014) against a real PostgreSQL
//! (`FERRUM_GRC_TEST_DATABASE_URL`, default `postgres://ferrum:ferrum@localhost:5432/ferrum_grc_test`;
//! reset first): risks scored inherent, current and residual, never worse with controls or as
//! targeted on the workspace's matrix; mitigation naming its controls; a risk above the tolerance accepted only by a risk
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

/// A framework library as a workspace's people would write one: a package with seed records only.
const EXAMPLE_LIBRARY: &str = r#"package: grc_lib_example
version: 0.1.0
label: "Example framework"
description: "A made-up framework for the suite"
depends: [grc]
seed:
  - entity: Framework
    key: [framework_name]
    records: [{framework_name: Example Framework, edition: "1"}]
  - entity: Requirement
    key: [framework, ref]
    records:
      - {framework: "@Framework:framework_name=Example Framework", ref: "1", title: Governance, assessable: false, sort_order: 1}
      - {framework: "@Framework:framework_name=Example Framework", ref: "1.1", title: A policy exists, parent_ref: "1", sort_order: 2}
"#;

fn example_library() -> ferrum_meta::Package {
    ferrum_meta::catalog::load_embedded(&[("grc_lib_example", "package.yaml", EXAMPLE_LIBRARY)]).expect("the example library").remove(0)
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
    // The connector to ITSM waits for a package this suite does not load; the others go in.
    packages.extend(ferrum_app_grc::packages().expect("app packages").into_iter().filter(|p| !p.manifest.depends.iter().any(|d| d == "itsm")));
    packages.push(example_library());
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
    let sql = |q: &'static str, id: Uuid| {
        let k = k.clone();
        async move {
            let mut tx = k.db.tenant_tx(tenant).await.unwrap();
            sqlx::query(q).bind(tenant).bind(id).execute(&mut *tx).await.unwrap();
            tx.commit().await.unwrap();
        }
    };
    let matrix = uid(&t.k.list(&rm, "GrcSettings", &ListQuery::default()).await.unwrap().rows[0]["id"]);
    // A three-point scale.
    let three = json!({"scale": 3, "medium_from": 3, "high_from": 5, "critical_from": 8, "tolerance": 2});
    t.set(&rm, "GrcSettings", matrix, three).await.expect("a three-point matrix");
    refused(t.k.insert(&rm, "Risk", obj(risk("Flood", "cfo@secure.test", [4, 3, 3, 3, 1, 1], "Open", json!([])))).await, "invalid", "from 1 to 3");
    let flood = uid(&t.insert(&rm, "Risk", risk("Flood", "cfo@secure.test", [3, 3, 3, 3, 1, 1], "Open", json!([]))).await["id"]);
    assert_eq!(t.get("Risk", flood).await["level"], "Critical", "9 on a three-point scale");
    let spill = uid(&t.insert(&rm, "Risk", risk("Coffee spill", "cfo@secure.test", [1, 2, 1, 2, 1, 1], "Open", json!([]))).await["id"]);
    assert_eq!(t.get("Risk", spill).await["level"], "Low");
    // Bands in the wrong order are refused; so is a tolerance above the scale squared.
    refused(t.set(&rm, "GrcSettings", matrix, json!({"high_from": 3})).await, "invalid", "rising order");
    refused(t.set(&rm, "GrcSettings", matrix, json!({"critical_from": 10})).await, "invalid", "rising order");
    refused(t.set(&rm, "GrcSettings", matrix, json!({"tolerance": 10})).await, "invalid", "a score on the matrix");
    // A workspace that changes nothing keeps today's levels: settings saved before this release (the matrix's columns
    // empty) score on five points with today's bands, which the upkeep brings every risk back to.
    sql(
        "update e_grc_settings set scale = null, medium_from = null, high_from = null, critical_from = null, tolerance = 6 where tenant_id = $1 and id = $2",
        matrix,
    )
    .await;
    ferrum_app_grc::maintenance_on(&k, tenant, today).await.unwrap();
    assert_eq!(t.get("Risk", flood).await["level"], "Medium", "9 on five points");
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
    // A risk says what could cause it and what it threatens.
    let phishing = uid(&t.insert(&rm, "Threat", json!({"threat_name": "Phishing"})).await["id"]);
    let theft = uid(&t.insert(&rm, "Threat", json!({"threat_name": "Laptop theft"})).await["id"]);
    let weak = uid(&t.insert(&rm, "Vulnerability", json!({"vulnerability_name": "Reused passwords"})).await["id"]);
    let cause = |threats: &[Uuid], vulns: &[Uuid]| {
        json!({"threats": threats.iter().map(|x| json!({"threat": x.to_string()})).collect::<Vec<_>>(),
               "vulnerabilities": vulns.iter().map(|x| json!({"vulnerability": x.to_string()})).collect::<Vec<_>>(),
               "assets": [{"asset": "Customer database", "note": "Main region"}, {"asset": "Payroll files"}]})
    };
    t.set(&rm, "Risk", ransom_id, cause(&[phishing, theft], &[weak])).await.expect("its causes and its stakes");
    let r = t.get("Risk", ransom_id).await;
    assert_eq!(["threats", "vulnerabilities", "assets"].map(|k| r[k].as_array().unwrap().len()), [2, 1, 2], "read back");
    // A threat is listed once on a risk; so is a vulnerability.
    refused(t.set(&rm, "Risk", ransom_id, cause(&[phishing, phishing], &[weak])).await, "invalid", "a threat is listed once");
    refused(t.set(&rm, "Risk", ransom_id, cause(&[phishing], &[weak, weak])).await, "invalid", "a vulnerability is listed once");
    // A switched-off threat is not added, and stays where it was.
    t.set(&rm, "Threat", theft, json!({"disabled": true})).await.unwrap();
    let flood_threat = uid(&t.insert(&rm, "Threat", json!({"threat_name": "River flood", "disabled": true})).await["id"]);
    refused(t.set(&rm, "Risk", small, cause(&[flood_threat], &[])).await, "invalid", "River flood is switched off");
    t.set(&rm, "Risk", ransom_id, json!({"description": "Encrypted shares"})).await.expect("Laptop theft stays on the risk");
    assert_eq!(t.get("Risk", ransom_id).await["threats"].as_array().unwrap().len(), 2);
    // Who may keep the libraries: not a Risk Approver, who reads them.
    refused(t.k.insert(&ra, "Threat", obj(json!({"threat_name": "Mine"}))).await, "forbidden", "");
    t.k.get(&ra, "Threat", phishing, false).await.expect("an approver reads a threat");
    // The scale does not shrink below a score in use.
    let five = |high: i64| json!({"scale": 5, "medium_from": 5, "high_from": high, "critical_from": 17});
    refused(
        t.set(&rm, "GrcSettings", matrix, json!({"scale": 4, "medium_from": 5, "high_from": 10, "critical_from": 16})).await,
        "invalid",
        "1 risks are scored above it",
    );
    assert_eq!(t.get("Risk", ransom_id).await["inherent_likelihood"], 5, "unchanged");
    // Changing the bands re-levels every risk at once.
    let fraud = uid(&t.insert(&rm, "Risk", risk("Invoice fraud", "cfo@secure.test", [5, 2, 5, 2, 1, 1], "Open", json!([]))).await["id"]);
    assert_eq!(t.get("Risk", fraud).await["level"], "High");
    t.set(&rm, "GrcSettings", matrix, five(12)).await.unwrap();
    assert_eq!(t.get("Risk", fraud).await["level"], "Medium", "10, below the new High, with no upkeep");
    t.set(&rm, "GrcSettings", matrix, five(10)).await.unwrap();
    assert_eq!((t.get("Risk", fraud).await["level"].as_str(), t.get("Risk", ransom_id).await["level"].as_str()), (Some("High"), Some("High")));
    // The upkeep heals a level written under old bands.
    sql("update e_risk set level = 'Low' where tenant_id = $1 and id = $2", fraud).await;
    ferrum_app_grc::maintenance_on(&k, tenant, today).await.unwrap();
    assert_eq!(t.get("Risk", fraud).await["level"], "High");
    // Who may change the matrix: not a Risk Approver.
    refused(t.set(&ra, "GrcSettings", matrix, five(12)).await, "forbidden", "");
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

    // ───────────── remediation plans: steps, and a retest before a finding closes ─────────────
    let step = |title: &str, done: bool| json!({"title": title, "owner": "ops@secure.test", "due_on": (today + Duration::days(5)).to_string(), "done": done});
    let mut planned = finding("Weak TLS on the VPN", (today + Duration::days(20)).to_string());
    planned["steps"] = json!([step("Disable TLS 1.0", true), step("Rescan", false)]);
    let weak = uid(&t.insert(&rm, "Finding", planned).await["id"]);
    // A step done is dated on the workspace's day, and undone loses the date.
    let steps = |d: &Doc| d["steps"].as_array().unwrap().iter().map(|r| r["done_on"].as_str().map(str::to_string)).collect::<Vec<_>>();
    assert_eq!(steps(&t.get("Finding", weak).await), [Some(today.to_string()), None]);
    t.set(&rm, "Finding", weak, json!({"steps": [step("Disable TLS 1.0", false), step("Rescan", false)]})).await.unwrap();
    assert_eq!(steps(&t.get("Finding", weak).await), [None, None]);
    // A finding with an open step does not close; with every step done it does.
    let closing = |steps: Value| json!({"status": "Closed", "remediation": "TLS 1.2 only", "steps": steps});
    refused(t.set(&rm, "Finding", weak, closing(json!([step("Disable TLS 1.0", true), step("Rescan", false)]))).await, "invalid", "1 steps are not done");
    t.set(&rm, "Finding", weak, closing(json!([step("Disable TLS 1.0", true), step("Rescan", true)]))).await.expect("every step done");
    // Who may change a finding's plan: not a Risk Approver.
    refused(t.set(&ra, "Finding", f2, json!({"steps": [step("Mine", false)]})).await, "forbidden", "");
    // A finding that needs a retest closes only with one, of its own control, effective, made after it was raised.
    let mut needs = finding("Admins without MFA", (today + Duration::days(20)).to_string());
    needs["retest_required"] = json!(true);
    let admins = uid(&t.insert(&rm, "Finding", needs).await["id"]);
    let close_with = |retest: Option<Uuid>| json!({"status": "Closed", "remediation": "Enforced", "retest": retest.map(|r| r.to_string())});
    refused(t.set(&rm, "Finding", admins, close_with(None)).await, "invalid", "the test that showed the fix works");
    let other = uid(&t.insert(&rm, "ControlTest", test(backups, today.to_string(), "Effective", proof.clone())).await["id"]);
    refused(t.set(&rm, "Finding", admins, close_with(Some(other))).await, "invalid", "is a test of this finding's control");
    let failed = uid(&t.insert(&rm, "ControlTest", test(mfa, today.to_string(), "Ineffective", json!([]))).await["id"]);
    refused(t.set(&rm, "Finding", admins, close_with(Some(failed))).await, "invalid", "found the control effective");
    let before = uid(&t.insert(&rm, "ControlTest", test(mfa, (today - Duration::days(1)).to_string(), "Effective", proof.clone())).await["id"]);
    refused(t.set(&rm, "Finding", admins, close_with(Some(before))).await, "invalid", "was made after the finding was raised");
    let retest = uid(&t.insert(&rm, "ControlTest", test(mfa, today.to_string(), "Effective", proof.clone())).await["id"]);
    t.set(&rm, "Finding", admins, close_with(Some(retest))).await.expect("closed with its retest");
    assert_eq!(t.get("Control", mfa).await["effective"], true, "the retest also stands for the control");

    // ───────────── attestation: who is asked to acknowledge a policy, by when, and who has not ─────────────
    let asks = |policy: Uuid| {
        let k = k.clone();
        let admin = t.admin.clone();
        async move {
            let q = ListQuery { filters: vec![ferrum_kernel::Filter::eq("policy", json!(policy.to_string()))], ..Default::default() };
            let mut rows: Vec<(String, i64, String)> = k
                .list(&admin, "PolicyAttestation", &q)
                .await
                .unwrap()
                .rows
                .iter()
                .map(|r| (r["person"].as_str().unwrap().to_string(), r["revision"].as_i64().unwrap(), r["status"].as_str().unwrap().to_string()))
                .collect();
            rows.sort();
            rows
        }
    };
    let ask_of = |policy: Uuid, person: &'static str, revision: i64| {
        let k = k.clone();
        async move {
            let mut tx = k.db.tenant_tx(tenant).await.unwrap();
            let id: Uuid = sqlx::query_scalar("select id from e_policy_attestation where tenant_id = $1 and policy = $2 and person = $3 and revision = $4")
                .bind(tenant)
                .bind(policy)
                .bind(person)
                .bind(revision)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            id
        }
    };
    // A policy with no audience behaves as before.
    let plain = uid(&t.insert(&rm, "Policy", json!({"title": "Visitors", "owner": "rm@secure.test", "text": "Sign in at the desk."})).await["id"]);
    assert_eq!(t.act(&rm, "Policy", plain, "publish").await.unwrap()["asked"], 0);
    assert!(asks(plain).await.is_empty(), "nobody asked");
    // Publishing asks each holder of the audience once.
    let handbook = uid(&t
        .insert(
            &rm,
            "Policy",
            json!({"title": "Handbook", "owner": "rm@secure.test", "text": "Be kind.", "audience_role": "Policy Reader", "acknowledge_within_days": 30}),
        )
        .await["id"]);
    assert_eq!(t.act(&rm, "Policy", handbook, "publish").await.unwrap()["asked"], 2);
    let due = (today + Duration::days(30)).to_string();
    assert_eq!(asks(handbook).await, [("pat@secure.test".into(), 1, "Due".into()), ("quinn@secure.test".into(), 1, "Due".into())]);
    let pat1 = ask_of(handbook, "pat@secure.test", 1).await;
    assert_eq!(t.get("PolicyAttestation", pat1).await["due_on"], json!(due));
    assert_eq!(
        (sends(pat1, "grc.policy_to_acknowledge").await, sends(ask_of(handbook, "quinn@secure.test", 1).await, "grc.policy_to_acknowledge").await),
        (1, 1)
    );
    refused(t.act(&rm, "Policy", handbook, "publish").await, "invalid", "nothing new to publish");
    assert_eq!(asks(handbook).await.len(), 2, "asks nobody again");
    // Acknowledging closes the person's own ask; someone not asked can still acknowledge, and gets no ask.
    t.act(&reader, "Policy", handbook, "acknowledge").await.unwrap();
    assert_eq!(t.get("PolicyAttestation", pat1).await["status"], "Acknowledged");
    t.act(&rm, "Policy", handbook, "acknowledge").await.expect("anyone who reads it may acknowledge");
    assert_eq!(asks(handbook).await.len(), 2);
    // A new revision asks again and withdraws the old asks.
    t.set(&rm, "Policy", handbook, json!({"text": "Be kind. Be on time."})).await.unwrap();
    assert_eq!(t.act(&rm, "Policy", handbook, "publish").await.unwrap()["asked"], 2);
    assert_eq!(
        asks(handbook).await,
        [
            ("pat@secure.test".into(), 1, "Acknowledged".into()),
            ("pat@secure.test".into(), 2, "Due".into()),
            ("quinn@secure.test".into(), 1, "Withdrawn".into()),
            ("quinn@secure.test".into(), 2, "Due".into())
        ]
    );
    // Two acknowledgements at once make one.
    let race = uid(&t.insert(&rm, "Policy", json!({"title": "Race", "owner": "rm@secure.test", "text": "0"})).await["id"]);
    for i in 1..=20 {
        t.set(&rm, "Policy", race, json!({"text": format!("revision {i}")})).await.unwrap();
        t.act(&rm, "Policy", race, "publish").await.unwrap();
        let (a, b) = tokio::join!(
            t.k.run_action(&reader2, "Policy", race, "acknowledge", Value::Null),
            t.k.run_action(&reader2, "Policy", race, "acknowledge", Value::Null)
        );
        assert!(a.is_ok() != b.is_ok(), "one of two at once: {a:?} {b:?}");
        refused(if a.is_err() { a } else { b }, "invalid", "already");
    }
    let mut tx = t.k.db.tenant_tx(t.tenant).await.unwrap();
    let acks: i64 = sqlx::query_scalar("select count(*) from e_policy_acknowledgement where tenant_id = $1 and policy = $2")
        .bind(t.tenant)
        .bind(race)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(acks, 20, "one per revision");
    // Someone who joins the role is asked by the upkeep; someone who leaves is released.
    let joe = t.user("joe@secure.test", &["Policy Reader"]).await;
    t.k.set_user_roles(&t.admin, reader2.user, &[]).await.unwrap();
    t.set(&rm, "GrcSettings", settings, json!({"reminder_days": 0})).await.unwrap();
    ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(1)).await.unwrap();
    let joe2 = ask_of(handbook, "joe@secure.test", 2).await;
    let pat2 = ask_of(handbook, "pat@secure.test", 2).await;
    assert_eq!(t.get("PolicyAttestation", joe2).await["due_on"], json!((today + Duration::days(31)).to_string()), "his day counts from when he joined");
    assert_eq!(sends(joe2, "grc.policy_to_acknowledge").await, 1);
    assert_eq!(t.get("PolicyAttestation", ask_of(handbook, "quinn@secure.test", 2).await).await["status"], "Withdrawn");
    // A reminder goes once before the day, even from two upkeeps at once; with reminder days 0, none.
    ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(16)).await.unwrap();
    assert_eq!(sends(pat2, "grc.policy_reminder").await, 0, "reminder days 0");
    t.set(&rm, "GrcSettings", settings, json!({"reminder_days": 14})).await.unwrap();
    let (a, b) = tokio::join!(
        ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(16)),
        ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(16))
    );
    a.unwrap();
    b.unwrap();
    assert_eq!((sends(pat2, "grc.policy_reminder").await, sends(joe2, "grc.policy_reminder").await), (1, 0), "14 days before hers; 15 before his, not yet");
    ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(17)).await.unwrap();
    assert_eq!((sends(pat2, "grc.policy_reminder").await, sends(joe2, "grc.policy_reminder").await), (1, 1), "once each");
    // A reader sees only their own asks; a Risk Manager sees who has not acknowledged.
    let mine = t.k.list(&joe, "PolicyAttestation", &ListQuery::default()).await.unwrap().rows;
    assert_eq!(mine.len(), 1, "joe's own ask");
    let open = ListQuery {
        filters: vec![ferrum_kernel::Filter::eq("policy", json!(handbook.to_string())), ferrum_kernel::Filter::eq("status", json!("Due"))],
        ..Default::default()
    };
    let mut not_yet: Vec<String> =
        t.k.list(&rm, "PolicyAttestation", &open).await.unwrap().rows.iter().map(|r| r["person"].as_str().unwrap().to_string()).collect();
    not_yet.sort();
    assert_eq!(not_yet, ["joe@secure.test", "pat@secure.test"], "who has not acknowledged the current revision");
    // Nobody but the app writes an attestation.
    refused(t.set(&rm, "PolicyAttestation", pat2, json!({"status": "Acknowledged"})).await, "forbidden", "");
    refused(
        t.k.insert(&rm, "PolicyAttestation", obj(json!({"policy": handbook.to_string(), "revision": 2, "person": "rm@secure.test"}))).await,
        "forbidden",
        "",
    );
    // Past its day an ask is overdue; retiring the policy withdraws it.
    ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(31)).await.unwrap();
    assert_eq!(
        (t.get("PolicyAttestation", pat2).await["overdue"].as_bool(), t.get("PolicyAttestation", joe2).await["overdue"].as_bool()),
        (Some(true), Some(false))
    );
    t.act(&reader, "Policy", handbook, "acknowledge").await.unwrap();
    let pat2_doc = t.get("PolicyAttestation", pat2).await;
    assert_eq!((pat2_doc["status"].as_str(), pat2_doc["overdue"].as_bool()), (Some("Acknowledged"), Some(false)));
    t.act(&rm, "Policy", handbook, "retire").await.unwrap();
    assert_eq!(t.get("PolicyAttestation", joe2).await["status"], "Withdrawn");

    // ───────────── frameworks and requirements ─────────────
    let fw = |name: &str| json!({"framework_name": name, "edition": "2026", "publisher": "Secure Co"});
    let ours = uid(&t.insert(&rm, "Framework", fw("Our baseline")).await["id"]);
    let req = |framework: Uuid, r: &str, under: Option<&str>, assessable: bool| json!({"framework": framework.to_string(), "ref": r, "title": format!("Requirement {r}"), "parent_ref": under, "assessable": assessable});
    // A framework's requirements form a tree.
    let heading = uid(&t.insert(&rm, "Requirement", req(ours, "A", None, false)).await["id"]);
    let a1 = uid(&t.insert(&rm, "Requirement", req(ours, "A.1", Some("A"), true)).await["id"]);
    let a2 = uid(&t.insert(&rm, "Requirement", req(ours, "A.2", Some("A"), true)).await["id"]);
    refused(t.k.insert(&rm, "Requirement", obj(req(ours, "B.1", Some("B"), true))).await, "invalid", "bring parents in first");
    // A reference is unique in its framework, and may repeat in another.
    let theirs = uid(&t.insert(&rm, "Framework", fw("Supplier code")).await["id"]);
    assert!(t.k.insert(&rm, "Requirement", obj(req(ours, "A.1", Some("A"), true))).await.is_err(), "A.1 twice in one framework");
    t.insert(&rm, "Requirement", req(theirs, "A", None, true)).await;
    // Nothing sits under itself.
    let x = uid(&t.insert(&rm, "Requirement", req(theirs, "X", None, true)).await["id"]);
    t.insert(&rm, "Requirement", req(theirs, "Y", Some("X"), true)).await;
    refused(t.set(&rm, "Requirement", x, json!({"parent_ref": "Y"})).await, "invalid", "under itself");
    refused(t.set(&rm, "Requirement", x, json!({"parent_ref": "X"})).await, "invalid", "is another requirement");
    // A sheet brings requirements in, parents first.
    let sheet = |order: &[&str]| order.iter().map(|r| req(theirs, r, r.rsplit_once('.').map(|(p, _)| p), true)).collect::<Vec<_>>();
    let (made, failed) = t.k.import_rows(&rm, "Requirement", &sheet(&["C", "C.1", "C.2", "C.1.1", "C.1.2"])).await.unwrap();
    assert_eq!((made.len(), failed.len()), (5, 0), "{failed:?}");
    let (made, failed) = t.k.import_rows(&rm, "Requirement", &sheet(&["D.1", "D"])).await.unwrap();
    assert_eq!(made.len(), 1);
    assert_eq!(failed[0]["row"], 0);
    assert!(failed[0].to_string().contains("parent_ref"), "{failed:?}");
    // A control answers requirements: each once, never a heading, never one of a framework switched off.
    let maps = |ids: &[Uuid]| json!({"requirements": ids.iter().map(|i| json!({"requirement": i.to_string()})).collect::<Vec<_>>()});
    t.set(&rm, "Control", mfa, maps(&[a1, a2])).await.expect("two requirements answered");
    refused(t.set(&rm, "Control", backups, maps(&[a1, a1])).await, "invalid", "A.1 is listed twice");
    refused(t.set(&rm, "Control", backups, maps(&[heading])).await, "invalid", "A is a heading");
    let off = uid(&t.insert(&rm, "Framework", json!({"framework_name": "Retired code", "disabled": true})).await["id"]);
    let z = uid(&t.insert(&rm, "Requirement", req(off, "Z", None, true)).await["id"]);
    refused(t.set(&rm, "Control", backups, maps(&[z])).await, "invalid", "switched off");
    t.set(&rm, "Framework", ours, json!({"disabled": true})).await.unwrap();
    t.set(&rm, "Control", mfa, json!({"description": "Every sign-in"})).await.expect("rows already there stay");
    assert_eq!(t.get("Control", mfa).await["requirements"].as_array().unwrap().len(), 2);
    t.set(&rm, "Framework", ours, json!({"disabled": false})).await.unwrap();
    // A requirement in use keeps its framework and reference.
    refused(t.set(&rm, "Requirement", a1, json!({"ref": "A.9"})).await, "invalid", "keeps its framework and reference");
    refused(t.set(&rm, "Requirement", heading, json!({"ref": "AA"})).await, "invalid", "keeps its framework and reference");
    t.set(&rm, "Requirement", a2, json!({"title": "Second, reworded"})).await.expect("its words may change");
    // A library installs its framework once.
    for _ in 0..2 {
        t.k.install_packages(tenant, &["grc_lib_example".to_string()]).await.expect("the library");
    }
    let mut tx = t.k.db.tenant_tx(t.tenant).await.unwrap();
    let seeded: (i64, i64) = sqlx::query_as(
        "select (select count(*) from e_framework where tenant_id = $1 and framework_name = 'Example Framework'), \
         (select count(*) from e_requirement r join e_framework f on f.tenant_id = r.tenant_id and f.id = r.framework \
          where r.tenant_id = $1 and f.framework_name = 'Example Framework')",
    )
    .bind(t.tenant)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(seeded, (1, 2), "made once");
    // Who may: a Risk Approver reads, and neither creates nor imports.
    refused(t.k.insert(&ra, "Framework", obj(fw("Mine"))).await, "forbidden", "");
    refused(t.k.import_rows(&ra, "Requirement", &sheet(&["E"])).await, "forbidden", "");
    assert!(!t.k.list(&ra, "Requirement", &ListQuery::default()).await.unwrap().rows.is_empty());

    // ───────────── compliance assessments ─────────────
    let base = uid(&t.insert(&rm, "Framework", fw("Assessment baseline")).await["id"]);
    t.insert(&rm, "Requirement", req(base, "H", None, false)).await;
    let r: Vec<Uuid> = {
        let mut v = vec![];
        for r in ["H.1", "H.2", "H.3", "H.4"] {
            v.push(uid(&t.insert(&rm, "Requirement", req(base, r, Some("H"), true)).await["id"]));
        }
        v
    };
    let control = |name: &str, status: &str, answers: &[Uuid]| {
        let mut c = json!({"control_name": name, "status": status});
        c["requirements"] = maps(answers)["requirements"].clone();
        c
    };
    let good = uid(&t.insert(&rm, "Control", control("Good control", "In Place", &[r[0], r[2]])).await["id"]);
    let bad = uid(&t.insert(&rm, "Control", control("Bad control", "In Place", &[r[1], r[2]])).await["id"]);
    t.insert(&rm, "Control", control("Planned control", "Planned", &[r[3]])).await;
    t.insert(&rm, "ControlTest", test(good, today.to_string(), "Effective", proof.clone())).await;
    t.insert(&rm, "ControlTest", test(bad, today.to_string(), "Ineffective", json!([]))).await;
    // A new assessment has a row per assessable requirement, and the controls speak for each.
    let asm =
        uid(&t.insert(&rm, "ComplianceAssessment", json!({"title": "2026 assessment", "framework": base.to_string(), "owner": "rm@secure.test"})).await["id"]);
    let rows_of = |d: &Doc| -> Vec<(Uuid, String, String, i64, Uuid)> {
        d["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| {
                (
                    uid(&x["requirement"]),
                    x["result"].as_str().unwrap().into(),
                    x["suggested"].as_str().unwrap().into(),
                    x["controls"].as_i64().unwrap(),
                    uid(&x["id"]),
                )
            })
            .collect()
    };
    let said = |d: &Doc| rows_of(d).into_iter().map(|(q, _, s, n, _)| (q, s, n)).collect::<Vec<_>>();
    assert_eq!(
        said(&t.get("ComplianceAssessment", asm).await),
        [
            (r[0], "Compliant".to_string(), 1),
            (r[1], "Non-Compliant".to_string(), 1),
            (r[2], "Partially Compliant".to_string(), 2),
            (r[3], "Not Assessed".to_string(), 0)
        ],
        "four rows, none for the heading"
    );
    // Refreshing adds what the framework gained and keeps what was entered.
    let set_results = |d: &Doc, results: &[(usize, &str)]| {
        let rows = rows_of(d);
        json!({"rows": rows.iter().enumerate().map(|(i, row)| match results.iter().find(|(j, _)| *j == i) {
            Some((_, res)) => json!({"id": row.4.to_string(), "result": res}),
            None => json!({"id": row.4.to_string()}),
        }).collect::<Vec<_>>()})
    };
    let d = t.get("ComplianceAssessment", asm).await;
    t.set(&rm, "ComplianceAssessment", asm, set_results(&d, &[(1, "Not Applicable")])).await.expect("a result entered");
    let r5 = uid(&t.insert(&rm, "Requirement", req(base, "H.5", Some("H"), true)).await["id"]);
    let out = t.act(&rm, "ComplianceAssessment", asm, "refresh_assessment").await.unwrap();
    assert_eq!((out["rows"].as_i64(), out["added"].as_i64()), (Some(5), Some(1)));
    let d = t.get("ComplianceAssessment", asm).await;
    assert_eq!((rows_of(&d)[1].1.as_str(), rows_of(&d)[4].0), ("Not Applicable", r5), "kept, and the new one appended");
    // Taking the suggestions fills only what was not assessed.
    assert_eq!(t.act(&rm, "ComplianceAssessment", asm, "accept_suggestions").await.unwrap()["taken"], 2);
    let results = |d: &Doc| rows_of(d).into_iter().map(|x| x.1).collect::<Vec<_>>();
    let d = t.get("ComplianceAssessment", asm).await;
    assert_eq!(results(&d), ["Compliant", "Not Applicable", "Partially Compliant", "Not Assessed", "Not Assessed"]);
    // It completes only when every requirement is assessed.
    refused(t.act(&rm, "ComplianceAssessment", asm, "complete_assessment").await, "invalid", "2 requirements are not assessed");
    // The counts and the coverage.
    t.set(&rm, "ComplianceAssessment", asm, set_results(&d, &[(3, "Compliant"), (4, "Not Applicable")])).await.unwrap();
    let d = t.get("ComplianceAssessment", asm).await;
    let counts = ["requirements", "compliant", "partial", "non_compliant", "not_applicable", "not_assessed"].map(|k| d[k].as_i64().unwrap());
    assert_eq!(counts, [5, 2, 1, 0, 2, 0]);
    let coverage = d["coverage"].as_str().map(|c| c.parse::<f64>().unwrap()).or(d["coverage"].as_f64());
    assert_eq!(coverage, Some(66.67), "two of the three that apply");
    let out = t.act(&rm, "ComplianceAssessment", asm, "complete_assessment").await.unwrap();
    assert_eq!(out["status"], "Complete");
    let done = t.get("ComplianceAssessment", asm).await;
    assert_eq!(done["completed_on"], json!(today.to_string()));
    refused(t.set(&rm, "ComplianceAssessment", asm, set_results(&done, &[(0, "Non-Compliant")])).await, "invalid", "kept as it was");
    for action in ["refresh_assessment", "accept_suggestions", "complete_assessment"] {
        refused(t.act(&rm, "ComplianceAssessment", asm, action).await, "invalid", "not available");
    }
    // Every row not applicable: no coverage. Rows come from the framework.
    let second =
        uid(&t.insert(&rm, "ComplianceAssessment", json!({"title": "Second look", "framework": base.to_string(), "owner": "rm@secure.test"})).await["id"]);
    let d = t.get("ComplianceAssessment", second).await;
    t.set(
        &rm,
        "ComplianceAssessment",
        second,
        set_results(&d, &[(0, "Not Applicable"), (1, "Not Applicable"), (2, "Not Applicable"), (3, "Not Applicable"), (4, "Not Applicable")]),
    )
    .await
    .unwrap();
    assert!(t.get("ComplianceAssessment", second).await["coverage"].is_null(), "nothing applies");
    let mut fewer = set_results(&d, &[]);
    fewer["rows"].as_array_mut().unwrap().pop();
    refused(t.set(&rm, "ComplianceAssessment", second, fewer).await, "invalid", "rows come from the framework");
    let mut more = set_results(&d, &[]);
    more["rows"].as_array_mut().unwrap().push(json!({"requirement": r[0].to_string(), "result": "Compliant"}));
    // A row's requirement is read-only, so the platform refuses a person's new row before the app's own words.
    refused(t.set(&rm, "ComplianceAssessment", second, more).await, "invalid", "Requirement is required");
    // Who may: a Risk Approver reads and is refused the actions; a Policy Reader does not read.
    t.k.get(&ra, "ComplianceAssessment", second, false).await.expect("an approver reads");
    refused(t.act(&ra, "ComplianceAssessment", second, "refresh_assessment").await, "forbidden", "");
    assert!(t.k.get(&reader, "ComplianceAssessment", second, false).await.is_err(), "a reader does not");
    // A control going stale later does not change a completed assessment.
    ferrum_app_grc::maintenance_on(&k, tenant, today + Duration::days(400)).await.unwrap();
    assert_eq!(t.get("Control", good).await["effective"], false, "stale by now");
    assert_eq!(rows_of(&t.get("ComplianceAssessment", asm).await), rows_of(&done), "as it was completed");

    // ───────────── incidents and the notices they owe ─────────────
    let notice_rule = |name: &str, hours: i64, personal: bool, from: &str| json!({"rule_name": name, "recipient": format!("{name} desk"), "hours": hours, "personal_data_only": personal, "from_severity": from});
    let authority = uid(&t.insert(&rm, "NoticeRule", notice_rule("Authority", 72, true, "Low")).await["id"]);
    let customers = uid(&t.insert(&rm, "NoticeRule", notice_rule("Customers", 24, false, "High")).await["id"]);
    let detected = Utc::now() - Duration::hours(80);
    let incident = |title: &str, severity: &str, personal: bool| json!({"title": title, "kind": "Data Breach", "severity": severity, "owner": "rm@secure.test", "detected_at": detected.to_rfc3339(), "personal_data_affected": personal});
    let when = |v: &Value| v.as_str().map(|x| chrono::DateTime::parse_from_rfc3339(x).unwrap().with_timezone(&Utc));
    let dues = |d: &Doc| {
        let mut v: Vec<(String, chrono::DateTime<Utc>)> =
            d["notices"].as_array().unwrap().iter().map(|n| (n["rule"].as_str().unwrap().to_string(), when(&n["due_at"]).unwrap())).collect();
        v.sort_by_key(|x| x.1);
        v
    };
    let close = |a: Option<chrono::DateTime<Utc>>, b: chrono::DateTime<Utc>| a.is_some_and(|a| (a - b).num_seconds().abs() <= 1);
    // An incident gets the notices its rules ask for.
    let leak = uid(&t.insert(&rm, "Incident", incident("Customer list leaked", "High", true)).await["id"]);
    let d = t.get("Incident", leak).await;
    let due = dues(&d);
    assert_eq!(due.iter().map(|x| x.0.clone()).collect::<Vec<_>>(), [customers.to_string(), authority.to_string()]);
    assert!(close(Some(due[0].1), detected + Duration::hours(24)) && close(Some(due[1].1), detected + Duration::hours(72)), "{due:?}");
    assert!(close(when(&d["next_notice_due"]), detected + Duration::hours(24)), "the earlier deadline");
    // A rule that does not apply gives no notice.
    let outage = uid(&t.insert(&rm, "Incident", incident("Mail outage", "High", false)).await["id"]);
    assert_eq!(dues(&t.get("Incident", outage).await).len(), 1, "no personal data: the customers' notice only");
    // A deadline passed unsent tells the owner once, even from two upkeeps at once.
    let (a, b) = tokio::join!(ferrum_app_grc::maintenance_on(&k, tenant, today), ferrum_app_grc::maintenance_on(&k, tenant, today));
    a.unwrap();
    b.unwrap();
    assert_eq!(t.get("Incident", leak).await["notice_overdue"], true);
    assert_eq!(sends(leak, "grc.incident_notice_overdue").await, 1);
    ferrum_app_grc::maintenance_on(&k, tenant, today).await.unwrap();
    assert_eq!(sends(leak, "grc.incident_notice_overdue").await, 1, "once");
    // Marking a notice sent moves on to the next deadline; all sent, none is next.
    let sent = Utc::now() - Duration::hours(1);
    let mark = |d: &Doc, which: &[Uuid]| {
        json!({"notices": d["notices"].as_array().unwrap().iter().map(|n| {
            let rule = uid(&n["rule"]);
            if which.contains(&rule) { json!({"id": n["id"], "sent_at": sent.to_rfc3339(), "reference": "case 1"}) } else { json!({"id": n["id"]}) }
        }).collect::<Vec<_>>()})
    };
    let d = t.get("Incident", leak).await;
    t.set(&rm, "Incident", leak, mark(&d, &[customers])).await.expect("the customers were told");
    let d = t.get("Incident", leak).await;
    assert!(close(when(&d["next_notice_due"]), detected + Duration::hours(72)), "on to the authority's");
    assert_eq!(d["notice_overdue"], false, "a later deadline is told in its turn");
    t.set(&rm, "Incident", leak, mark(&d, &[customers, authority])).await.unwrap();
    let d = t.get("Incident", leak).await;
    assert!(d["next_notice_due"].is_null() && d["notice_overdue"] == false);
    // A sent notice survives its rule being switched off; an unsent one goes.
    t.set(&rm, "NoticeRule", customers, json!({"disabled": true})).await.unwrap();
    t.set(&rm, "Incident", leak, json!({"description": "Exported by mistake"})).await.unwrap();
    t.set(&rm, "Incident", outage, json!({"description": "Relay down"})).await.unwrap();
    assert_eq!((dues(&t.get("Incident", leak).await).len(), dues(&t.get("Incident", outage).await).len()), (2, 0));
    // Times are in order.
    let mut early = incident("Back to front", "Low", false);
    early["contained_at"] = json!((detected - Duration::hours(1)).to_rfc3339());
    refused(t.k.insert(&rm, "Incident", obj(early)).await, "invalid", "is after it was detected");
    let mut future = incident("Not yet", "Low", false);
    future["detected_at"] = json!((Utc::now() + Duration::hours(2)).to_rfc3339());
    refused(t.k.insert(&rm, "Incident", obj(future)).await, "invalid", "is now or before");
    // A resolved incident says what was learned, and is dated when resolved.
    refused(t.set(&rm, "Incident", outage, json!({"status": "Resolved"})).await, "invalid", "says what was learned");
    t.set(&rm, "Incident", outage, json!({"status": "Resolved", "lessons": "A second relay"})).await.unwrap();
    assert!(t.get("Incident", outage).await["resolved_at"].as_str().is_some(), "dated");
    // Who may: a Risk Approver reads and cannot write; a Policy Reader does not read.
    t.k.get(&ra, "Incident", leak, false).await.expect("an approver reads");
    refused(t.set(&ra, "Incident", leak, json!({"description": "x"})).await, "forbidden", "");
    assert!(t.k.get(&reader, "Incident", leak, false).await.is_err());
    // A finding names its incident.
    let mut from_incident = finding("Exports not reviewed", (today + Duration::days(20)).to_string());
    from_incident["incident"] = json!(leak.to_string());
    let f = uid(&t.insert(&rm, "Finding", from_incident).await["id"]);
    assert_eq!(t.get("Finding", f).await["incident"], json!(leak.to_string()));

    // ───────────── who may do what ─────────────
    refused(t.k.insert(&ra, "Risk", obj(risk("Mine", "ra@secure.test", [1, 1, 1, 1, 1, 1], "Open", json!([])))).await, "forbidden", "");
    refused(t.k.insert(&reader, "Policy", obj(json!({"title": "Mine", "text": "x"}))).await, "forbidden", "");
    refused(t.k.insert(&ra, "ControlTest", obj(test(backups, today.to_string(), "Ineffective", json!([])))).await, "forbidden", "");

    // ───────────── the package says where people's data is, and what each action promises ─────────────
    let grc = ferrum_app_grc::packages().unwrap().into_iter().find(|p| p.name() == "grc").unwrap();
    let mut declared: Vec<&str> = grc.manifest.personal_data.iter().map(|d| d.entity.as_str()).collect();
    declared.sort();
    declared.dedup();
    assert_eq!(
        declared,
        [
            "ComplianceAssessment",
            "Control",
            "ControlTest",
            "Finding",
            "Incident",
            "Policy",
            "PolicyAcknowledgement",
            "PolicyAttestation",
            "Risk",
            "RiskAcceptance"
        ]
    );
    let mut handed: Vec<&str> = grc.manifest.handover.iter().map(|h| h.entity.as_str()).collect();
    handed.sort();
    assert_eq!(handed, ["ComplianceAssessment", "Control", "Finding", "Incident", "Policy", "Risk"]);
    let theirs = t.k.personal_data(&t.admin, "rm@secure.test").await.expect("their data").to_string();
    for f in [f1, f2, f3, quiet] {
        assert!(theirs.contains(&f.to_string()), "the findings rm owns are hers: {f}");
    }
    let actions: Vec<_> = grc.entities.iter().flat_map(|e| e.actions.iter()).collect();
    assert_eq!(actions.len(), 9);
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
