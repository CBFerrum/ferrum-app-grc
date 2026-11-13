<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/banner-dark.svg">
  <img alt="Ferrum Governance and Risk: risks, controls, policies and findings in one register" src="docs/assets/banner-light.svg" width="100%">
</picture>

<br>

[![Version](https://img.shields.io/badge/version-0.1.16-7c3aed?style=flat-square)](CHANGELOG.md)
[![Licence: AGPL-3.0](https://img.shields.io/badge/licence-AGPL--3.0-blue?style=flat-square)](LICENSE)
[![Ferrum platform](https://img.shields.io/badge/runs%20on-Ferrum-2f5bea?style=flat-square)](https://github.com/CBFerrum/Ferrum)
![Rust](https://img.shields.io/badge/Rust-server-b7410e?style=flat-square&logo=rust)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-data-336791?style=flat-square&logo=postgresql&logoColor=white)
![React](https://img.shields.io/badge/React%20%2B%20TypeScript-interface-149eca?style=flat-square&logo=react&logoColor=white)

### Know your risks, prove your controls work, and keep people reading the rules.

Ferrum Governance and Risk is for security, compliance and operations teams who run their risk register, control
tests, policies and audit findings in spreadsheets and shared folders. It scores each risk three ways, ties it to
the controls that keep it down, asks for evidence before a control counts as working, and records who accepted
what and until when.

[💡 Why](#-why-governance-and-risk) · [📸 Screenshots](#-screenshots) · [✨ Features](#-features) · [📊 Compare](#-how-it-compares) · [📍 Roadmap](#-roadmap) · [🚀 Install](#-install) · [🔧 Develop](#-develop)

</div>

## 💡 Why Governance and Risk

- 🎯 **Three scores, not one.** Every risk is scored before controls, with them, and as targeted. The app refuses
  a score that makes no sense, such as controls that make a risk worse.
- 🧪 **A control is effective only with proof.** A control counts as working while its latest test passed, carried
  evidence, and is still current. Upkeep marks stale ones for a new test.
- 🔏 **Accepting risk is a decision.** A risk above your tolerance is accepted only with an acceptance, approved by
  someone who does not own the risk, for a stated time. When it ends, the risk is open again.
- 📜 **Policies by revision.** Publishing new text makes a new revision, keeps the text as published, and asks
  everyone to acknowledge it again.
- 🏠 **Self-hosted and open source.** AGPL-3.0, on your own server and database.
- 🧩 **Framework neutral.** No ISO, SOC 2 or NIST text is bundled and no certification is claimed. A control names
  the requirements it answers by their identifiers, so you use the framework your auditor does.
- 🌍 **One platform.** The same records, roles, audit trail, search and assistant as the rest of Ferrum.

## 🎯 At a glance

| | |
|---|---|
| **Version** | 0.1.16 (platform `>=0.3.2, <0.4`) |
| **Kind** | Own interface at `/grc/`, plus Ferrum's generic records screens for every entity |
| **What it adds** | 7 entities and a settings record (Risk, Control, Control Test, Risk Acceptance, Policy, Policy Acknowledgement, Finding), 2 child tables, 3 roles, 1 menu module, 3 numbered record types |
| **Depends on** | Ferrum core only |
| **Works with** | The Ferrum assistant, audit trail, notifications and Studio; no other app is required |
| **Languages** | English, Arabic (right to left), Hindi; a workspace can change any interface word |
| **Tests** | 3 Rust tests (one walks a whole security programme end to end) and UI tests |
| **Licence** | AGPL-3.0-only |

## 📸 Screenshots

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/screens/grc-home-dark.webp">
  <img alt="Governance and Risk home" src="docs/assets/screens/grc-home-light.webp" width="100%">
</picture>

**🛡️ The register**<br><sub>See open findings, controls waiting for a test, the risks with the worst first, and the policies in force.</sub>

<table>
<tr>
<td width="50%" valign="top">
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/screens/grc-risk-list-dark.webp"><img alt="Risk register" src="docs/assets/screens/grc-risk-list-light.webp"></picture>
<p><b>📋 Risk register</b><br><sub>Browse, search and filter risks by score, level, owner and treatment.</sub></p>
</td>
<td width="50%" valign="top">
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/screens/grc-risk-detail-dark.webp"><img alt="Risk record" src="docs/assets/screens/grc-risk-detail-light.webp"></picture>
<p><b>🎯 Risk record</b><br><sub>Score one risk three ways, name its controls and choose how it is treated.</sub></p>
</td>
</tr>
<tr>
<td width="50%" valign="top">
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/screens/grc-control-list-dark.webp"><img alt="Controls" src="docs/assets/screens/grc-control-list-light.webp"></picture>
<p><b>🧰 Controls</b><br><sub>See each control's status, last test and whether it is effective now.</sub></p>
</td>
<td width="50%" valign="top">
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/screens/grc-control-tests-dark.webp"><img alt="Control tests" src="docs/assets/screens/grc-control-tests-light.webp"></picture>
<p><b>🧪 Control tests</b><br><sub>See which controls have been tested, by whom, and how they fared.</sub></p>
</td>
</tr>
<tr>
<td width="50%" valign="top">
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/screens/grc-policy-list-dark.webp"><img alt="Policies" src="docs/assets/screens/grc-policy-list-light.webp"></picture>
<p><b>📜 Policies</b><br><sub>See each policy's owner, revision and state.</sub></p>
</td>
<td width="50%" valign="top">
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/screens/grc-policy-detail-dark.webp"><img alt="Policy record" src="docs/assets/screens/grc-policy-detail-light.webp"></picture>
<p><b>📖 Policy record</b><br><sub>Read a policy as published and acknowledge it with one click.</sub></p>
</td>
</tr>
<tr>
<td width="50%" valign="top">
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/screens/grc-finding-list-dark.webp"><img alt="Findings" src="docs/assets/screens/grc-finding-list-light.webp"></picture>
<p><b>🔎 Findings</b><br><sub>Track what an audit or a test found until each finding is closed with its fix.</sub></p>
</td>
<td width="50%" valign="top">
</td>
</tr>
</table>

<table>
<tr>
<td align="center" valign="top">
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/screens/grc-home-phone-dark.webp"><img alt="Register home on a phone" src="docs/assets/screens/grc-home-phone-light.webp" width="260"></picture>
<p><b>📱 Register on a phone</b></p>
</td>
<td align="center" valign="top">
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/screens/grc-risk-list-phone-dark.webp"><img alt="Risk register on a phone" src="docs/assets/screens/grc-risk-list-phone-light.webp" width="260"></picture>
<p><b>📱 Risks on a phone</b></p>
</td>
</tr>
</table>

## ✨ Features

### 🎯 The risk register

- **Risk.** Something that could go wrong, with a title, description, category (Strategic, Operational, Financial,
  Compliance, Security, Reputational), an owner, a review-by date and a number such as `RSK-2026-0001`.
- **Three scores.** Inherent (before controls), current (with them) and residual (as targeted). Each is
  likelihood times impact on a five-by-five matrix, so from 1 to 25. The three scores are worked out for you.
- **Level.** Low (up to 4), Medium (5 to 9), High (10 to 16) or Critical (17 to 25), taken from the current score.
- **Sense checks.** Likelihood and impact are from 1 to 5. Controls never make a risk worse than it is without
  them, and the target is never worse than the risk now. The form refuses anything else, with the reason.
- **Treatment.** Open, Mitigate, Accept, Avoid or Transfer.
- **Mitigate** names the controls that do it: a table of controls on the risk. A mitigated risk with no
  controls is refused.
- **Accept** above the tolerance only with an approved acceptance. The tolerance is a setting (default 6 out of 25).
- **Worst first.** The home page lists risks by level, then by score.

### 🔏 Risk acceptance

- **Risk Acceptance.** Says why a risk above the tolerance is taken on, and until when. It starts as a Draft and
  needs an expiry day after today. Numbered `ACC-2026-0001`.
- **Accept It, Reject It.** Only a Risk Approver decides, and never the risk's owner. Accepting sets the risk's
  treatment to Accept and records the approver and the day.
- **Revoke It.** A Risk Approver can take an accepted risk back. The risk is open again, unless another
  acceptance still holds it.
- **Expiry.** At the next upkeep an accepted risk whose day has passed becomes Expired and the risk is open
  again, unless another acceptance still holds it.
- **States.** Draft, Accepted, Rejected, Revoked and Expired.

### 🧰 Controls and tests

- **Control.** What is done to keep a risk down: a unique name, category (Policy, Process, Technical, Physical),
  owner, status (Planned, In Place, Retired), the framework requirements it answers (identifiers as text) and a
  description.
- **Control Test.** A test of a control on a day, with a result (Effective, Partially Effective, Ineffective),
  who tested it (filled in for you), notes and evidence.
- **Rules a test must follow.** The control must be In Place. The day cannot be in the future. An Effective
  result needs evidence: at least one evidence row with its file attached.
- **Evidence.** A table of titled files on the test.
- **Standing.** The control shows its last test day, last result and whether it is effective. It is effective
  while its latest test by day was Effective and is still current.
- **Stale tests.** A test is current for the number of days in the settings (default 365). Upkeep marks a control
  whose latest test has gone stale as no longer effective, so it appears in "Controls to test".

### 📜 Policies

- **Policy.** A unique title, owner, text (markdown), a review-by date and a state (Draft, Published, Retired).
- **Publish It.** Publishes the text. If the text changed, the policy moves to its next revision and keeps the
  text as published, with the day. Publishing the same text again is refused.
- **I Have Read It.** A person acknowledges the current revision once. A second try says it is done already.
- **Policy Acknowledgement.** A record of who read which revision and when. People cannot edit it.
- **Retire It.** A retired policy is no longer read.
- **Policy Reader.** A role that reads only published policies and sees its own acknowledgements.
- **Revision rule.** A person has acknowledged a policy when they acknowledged its current revision, so a new
  revision asks everyone again.

### 🔎 Findings

- **Finding.** Something an audit or a test found wrong: title, severity (Low, Medium, High, Critical), the
  control and risk it concerns, an owner, a due day and a number such as `FND-2026-0001`.
- **States.** Open, Remediating, Closed.
- **Overdue.** Upkeep marks a finding left open past its day as overdue. Closed, it is no longer overdue.
- **Closing needs a fix.** A closed finding must say how it was fixed in Remediation.

### ⚙️ Settings

| Setting | What it does |
|---|---|
| **Tolerance** | The highest score, out of 25, that is accepted without a risk acceptance (default 6). |
| **Test every (days)** | How long a control's test counts as current (default 365). |

### 🔐 Roles and access

- **Risk Manager.** Keeps the register, controls, tests, acceptances in draft, policies and findings, and the settings.
  Exports risks, controls, tests, findings and acknowledgements.
- **Risk Approver.** Decides acceptances. Reads risks and controls.
- **Policy Reader.** Reads published policies and acknowledges them.
- **Separation of duties.** The owner of a risk cannot approve taking it on. Nobody but an approver decides.
- **Audit trail.** Every change to every record is kept by the platform.

### 🌍 Interface

- **Its own pages.** `/grc/` shows four queues: open findings (overdue ones flagged), controls to test, risks
  worst first with a level colour, and policies with their revision.
- **Languages.** Arabic and Hindi words and names, with right-to-left layout.
- **Assistant.** The Ferrum assistant knows what the records mean and suggests questions such as "What are our
  highest risks after their controls?" and "Who has not acknowledged the current revision of a policy?"
- **Phone.** The pages work on a phone's browser.

## 🧭 How it works

```mermaid
flowchart LR
    R["Risk"] -->|"treatment: Mitigate"| C["Controls"]
    C -->|"tested with evidence"| T["Control Test"]
    T -->|"effective and current"| E["Control effective"]
    R -->|"above tolerance"| A["Risk Acceptance (draft)"]
    A -->|"Accept It by an approver"| AC["Accepted until a day"]
    AC -->|"Expired or revoked"| R
    T -->|"a gap is found: record it"| F["Finding"]
    F -->|"Closed with a fix"| D["Done"]
```

A risk is mitigated by controls that are tested, or accepted for a time by someone who does not own it. A gap that a test
or an audit finds is recorded as a finding, which an owner closes with a fix. Upkeep keeps the clock: it expires
acceptances, marks stale controls and flags overdue findings.

```mermaid
flowchart LR
    P["Policy (draft)"] -->|"Publish It"| V["Published, revision n"]
    V -->|"I Have Read It"| K["Acknowledgement of revision n"]
    V -->|"New text, Publish It"| W["Published, revision n+1"]
    W -->|"everyone again"| K
    V -->|"Retire It"| X["Retired"]
```

Each person acknowledges each revision once. New text means a new revision and a new round.

## 🧱 Data model

| Entity | What it is | Key fields or states |
|---|---|---|
| **Risk** | Something that could go wrong | Number, title, category, owner, three likelihood and impact pairs, three scores, level, treatment, controls, review by |
| **Control** | What keeps a risk down | Name, category, owner, status (Planned, In Place, Retired), references, last tested on, last result, effective |
| **Control Test** | A test on a day | Control, tested on, tester, result, evidence rows, notes |
| **Risk Acceptance** | A risk taken on for a time | Number, risk, justification, expires on, status, approver, decided on |
| **Policy** | What people follow | Title, owner, text, status, revision, published text, published on, review by |
| **Policy Acknowledgement** | Who read which revision | Policy, revision, person, acknowledged at |
| **Finding** | A gap an audit or test found | Number, title, severity, control, risk, owner, due on, status, remediation, overdue |
| **Governance Settings** | Workspace settings | Tolerance, test interval |
| Control on a risk (child) | A control named by a risk | Control |
| Evidence (child) | A file on a test | Title, file |

| Role | What it can do |
|---|---|
| **Risk Manager** | Keeps risks, controls, tests, acceptances in draft, policies, findings and the settings |
| **Risk Approver** | Accepts, rejects or revokes acceptances; reads risks and controls |
| **Policy Reader** | Reads published policies and acknowledges them |

The app ships no reports and no print formats. Use the platform's report builder and Studio for those. Upkeep
(on a schedule) expires acceptances, marks stale controls and flags overdue findings.

## 🔌 Integrations

| With | How | Needs |
|---|---|---|
| **Ferrum platform** | Roles, audit trail, search, notifications, the assistant, Studio and the report builder | Platform core |
| **Customize and Studio** | Add fields to any record, rules, automations and your own reports | Studio rights |
| **Other Ferrum apps** | Records live in one database, so a report or automation can read them | None; no connector ships yet |
| **Outside systems** | None yet: no cloud, identity or ticketing connector, and no framework libraries are included | Planned |

## 📊 How it compares

Compared with ServiceNow GRC (Integrated Risk Management), Archer, MetricStream, Vanta and Drata
(compliance automation, treated as one column), and Eramba (open source).

| Capability | Ferrum GRC | ServiceNow | Archer | MetricStream | Vanta / Drata | Eramba |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Risk register with scoring | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Inherent, current and residual scores | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ |
| Custom matrices and scales | ❌ | ✅ | ✅ | ✅ | 🟡 | 🟡 |
| Assets, threats and vulnerabilities on risks | ❌ | ✅ | ✅ | ✅ | 🟡 | ✅ |
| Control library with owners and status | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Control tests that need evidence | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Frameworks and requirements with control mapping | 🟡¹ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Compliance assessment and coverage across frameworks | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Automated evidence from cloud, identity and code systems | ❌ | 🟡 | 🟡 | 🟡 | ✅ | ❌ |
| Risk acceptance with approver and expiry | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ |
| Several approvers and reminders before expiry | ❌ | ✅ | ✅ | ✅ | 🟡 | 🟡 |
| Policy revisions kept | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Acknowledgement of each revision | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| Attestation campaigns with audience and reminders | ❌ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| Findings with owner, severity and due day | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ |
| Remediation plans with milestones and retest | 🟡² | ✅ | ✅ | ✅ | 🟡 | 🟡 |
| Audit engagements and auditor access | ❌ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| Vendor and third-party risk | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Business continuity and impact analysis | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| Incident and breach register | ❌ | ✅ | ✅ | ✅ | 🟡 | ✅ |
| Trust centre and security questionnaires | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Heat maps, dashboards and board reports | 🟡³ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Shared platform with IT, HR and asset records | 🟡⁴ | ✅ | 🟡 | 🟡 | 🟡 | 🟡 |
| Self-hosted | ✅ | ❌ | ✅ | 🟡⁵ | ❌ | ✅ |
| Open source | ✅ | ❌ | ❌ | ❌ | ❌ | 🟡⁶ |

¹ A control names the requirements it answers by identifier, as text. There is no framework library.
² One remediation text and three finding states; no milestones or retest.
³ The home page lists queues; there is no heat map or shipped report.
⁴ Same platform and database as the other Ferrum apps; no connector that collects evidence from them yet.
⁵ On-premises or private cloud options exist for some products.
⁶ Eramba has a free community edition and a paid enterprise edition.

### 🏆 Where Governance and Risk stands out

- 🔏 **Accepting risk is a controlled decision** with an approver who is not the owner, a reason and an expiry that
  reopens the risk by itself.
- 🧪 **Evidence is required**, and a control stops counting as working when its test goes stale.
- 📜 **Revision-aware policies**: new text means a new revision and a new round of acknowledgements.
- 🧩 **Framework neutral**, with no bundled text to license and no certification claimed.
- 🏠 **Self-hosted, open source, one platform**, with the audit trail, roles and assistant of the rest of Ferrum.
- 🌍 **Arabic and Hindi**, right-to-left layout.

### 🚧 Where the leaders are still ahead

- 📚 **Framework libraries** with requirement mapping and assessment of coverage across frameworks.
- 🤖 **Automated evidence** and continuous control monitoring from cloud, identity, HR and code systems.
- 🧑‍⚖️ **Audit engagements** with an auditor portal, request lists and sampling.
- 🏢 **Vendor risk**, business continuity and incident registers.
- 📈 **Reports**: heat maps, coverage and board packs.
- 🧮 **Risk depth**: assets, threats, vulnerabilities and custom matrices.

> [!NOTE]
> Leader columns are from public product information as of November 2026 and may change.

## 📍 Roadmap

### ✅ Recently shipped

- [x] **0.1.16.** Rebuilt on the tuned design system: better menu icons, a lighter first page, cleaner print.
- [x] **0.1.15.** The redesigned interface with shaped loading, told-apart states and the work-home pattern.
- [x] **0.1.14.** Names of the models, fields and menus in Arabic and Hindi.
- [x] **0.1.13.** The assistant knows the records and suggests questions.
- [x] **0.1.12.** Its own words in Arabic and Hindi.
- [x] **0.1.0.** Risks on a matrix with treatment and acceptance, controls tested with evidence, policies acknowledged by revision, and findings.

### 🔜 Next up

- [ ] **Framework libraries.** Frameworks and requirements mapped to controls, with coverage, because every audit asks for it.
- [ ] **Compliance assessments** of a framework against the controls in place.
- [ ] **Policy attestation campaigns** with an audience, reminders and a list of who has not acknowledged.
- [ ] **Several approvers** on an acceptance, and reminders before it expires.
- [ ] **Reports**: risk heat map, control coverage, overdue findings and an audit export.
- [ ] **Test assignment.** A test due on a day for a named tester.

### 🔭 Later

**Risk depth**
- [ ] Assets, threats and vulnerabilities on risks.
- [ ] Risk matrices other than five by five, and level thresholds as a setting.
- [ ] Key risk indicators.

**Evidence and monitoring**
- [ ] Evidence collected automatically from other apps and from cloud, identity and repository systems.
- [ ] Recurring compliance tasks with owners, reminders and evidence.
- [ ] People compliance from HR and learning records.

**Audit and findings**
- [ ] Audit engagements: auditor access for a time, request lists, sampling and workpapers.
- [ ] Remediation plans with milestones and retest.
- [ ] Scoping by business unit, and delegated risk owners.

**Wider governance**
- [ ] Vendor and third-party risk with questionnaires and reassessment.
- [ ] Incident and breach register with notification timers.
- [ ] Trust centre and security-questionnaire answering.
- [ ] Business continuity and impact analysis.

## 🚀 Install

Governance and Risk is a native Ferrum app, compiled into the Ferrum server. A workspace gets it from the App
Manager or the store. It needs platform `>=0.3.2, <0.4` and nothing else: it depends on Ferrum core only.

1. Install Governance and Risk.
2. Open Governance Settings: set the tolerance (the highest score accepted without an acceptance) and how many
   days a control's test counts as current.
3. Give people the roles: Risk Manager, Risk Approver and Policy Reader. Use a different person as approver from
   a risk's owner.
4. Add your controls and set them In Place. Write the identifiers of the framework requirements each answers.
5. Add risks, score them, and link controls to the ones you mitigate.
6. Publish your policies and ask people to open `/grc/` and press I Have Read It.

## 🔧 Develop

```bash
# server (needs a PostgreSQL role that is not a superuser, so row-level security applies)
export FERRUM_GRC_TEST_DATABASE_URL=postgres://ferrum:ferrum@localhost:5432/ferrum_grc_test
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The interface is built with Ferrum-Frontend, checked out next to this repository as `../ferrum/web`:

```bash
cd ui
npm run build       # writes ui/dist, which is committed and embedded by build.rs
npm run check
npm run typecheck
npm test
```

`tests/grc_it.rs` walks a security programme: controls tested and their standing going stale, risks scored and
refused when they make no sense, an acceptance approved, expired, revoked and rejected, a policy published twice
and acknowledged, findings overdue and closed, and who may do what.

## 📂 Project layout

```
app.yaml                      the app's manifest (version, roles, shell entries, assistant notes)
Cargo.toml, build.rs          the Rust crate; build.rs embeds packages/ and ui/dist
src/
  lib.rs                      registers the package, hooks and the upkeep
  risks.rs                    scoring, treatment rules, acceptances and their expiry
  controls.rs                 tests, standing, stale controls and findings
  policies.rs                 publish, revisions, acknowledgement and retire
packages/grc/                 entities, roles and the menu module
ui/src/                       the interface at /grc/ (home queues, locales ar and hi)
tests/grc_it.rs               the security-programme walk
docs/PROVENANCE.md            where the design comes from
```

## 📜 Changelog

Every release is described in [CHANGELOG.md](CHANGELOG.md).

## 🤝 Contributing

Issues and pull requests are welcome at [github.com/CBFerrum/ferrum-app-grc/issues](https://github.com/CBFerrum/ferrum-app-grc/issues).
Run the checks in [Develop](#-develop) first.

## 📄 License

AGPL-3.0-only. See [LICENSE](LICENSE).

<div align="center">

<sub>Part of <a href="https://github.com/CBFerrum/Ferrum">Ferrum</a>, the open business platform · Made with 🦀 Rust and 🐘 PostgreSQL</sub>

</div>
