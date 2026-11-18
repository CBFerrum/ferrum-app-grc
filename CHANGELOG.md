# Changelog

## 0.9.0

Needs the same platform as 0.8.0. Package `grc` 0.8.0: entities Threat and Vulnerability and three tables on Risk
(threats, vulnerabilities, assets). New connector package `grc_itsm` 0.1.0 (a configuration item on an asset row
and on a control, where ITSM is installed). Existing risks have empty tables. `ui/dist` rebuilt for the new names.

- **What could cause a risk and what it threatens.** Threats and vulnerabilities are the workspace's libraries,
  each listed once on a risk; one switched off is not added and stays where it was. Assets are named on the risk.
- **IT's records.** With ITSM installed, an asset and a control can name a configuration item. GRC works unchanged
  without it.

## 0.8.0

Needs the same platform as 0.7.0. Package `grc` 0.7.0: entity Assessment (`ComplianceAssessment`) with its rows
and three actions. Nothing changes for existing records. `ui/dist` rebuilt: the home's Assessments queue.

- **Assess a framework.** A row per assessable requirement, what its controls say today beside the assessor's
  result, counts and coverage. Refresh It, Use What the Controls Say (only rows not yet assessed) and Complete It
  (when every row is assessed), each with its contract. A completed assessment is kept as it was.

## 0.7.0

Needs the same platform as 0.6.0. Package `grc` 0.6.0: entities Framework and Requirement, and a Requirements
table on Control. New package `grc_lib_nist_csf` 0.1.0 (seed records only). Existing controls keep their
References text; nothing converts it. `ui/dist` rebuilt for the new names.

- **Frameworks and requirements are records.** Requirements form a tree by reference, unique in their framework;
  a sheet brings them in parents first; nothing sits under itself; one in use keeps its reference.
- **A control maps the requirements it answers,** each once, never a heading, never one of a framework switched off.
- **Libraries are data.** A library is a package of seed records on `grc` (README, "Writing a framework library").
  Shipped: the NIST Cybersecurity Framework 2.0's functions and categories, identifiers and titles, public domain.

## 0.6.0

Needs the same platform as 0.5.0. Package `grc` 0.5.0: a child table of steps on Finding (`FindingStep`) and two
Finding fields (`retest_required`, `retest`). Existing findings have no steps and need no retest: they close as
before. `ui/dist` rebuilt for the new names.

- **A fix has steps.** Each with an owner, a day and a done mark, dated on the workspace's day when ticked. A
  finding closes only when every step is done.
- **A retest before it closes.** A finding can require one: it closes only with a test of its own control, made on
  or after the day it was raised, that found the control effective.
- People named on steps are declared as personal data (kept as the audit record).

## 0.5.0

Needs the same platform as 0.4.0. Package `grc` 0.4.0: four Governance Settings fields (`scale`, `medium_from`,
`high_from`, `critical_from`). Settings saved before read the empty fields as five points with 5, 10 and 17,
which are the levels of before, so no risk changes; the backfill `grc_matrix_defaults` writes those values in. `ui/dist` rebuilt for the new words.

- **The matrix is the workspace's.** Likelihood and impact are scored from 1 to the scale (2 to 10), and the scores
  at which a risk becomes Medium, High and Critical are settings. Bands must rise and stay on the matrix; the
  tolerance must be a score on it; the scale cannot shrink below a score a risk holds (refused, never clamped).
- **Re-levelled at once.** Saving new bands re-levels every risk in the same transaction; the upkeep heals a risk
  saved under the old bands at the moment they changed.

## 0.4.0

Needs the same platform as 0.3.0. Package `grc` 0.3.0: new entity Attestation (`PolicyAttestation`), two Policy
fields (`audience_role`, `acknowledge_within_days`) and a unique key on Policy Acknowledgement (policy, revision,
person). An existing workspace's policies have no audience, so nothing is asked and nothing changes. `ui/dist`
rebuilt: the home's "To acknowledge" queue.

- **Who is asked, by when, and who has not.** A policy names an audience role and the days people have. Publishing
  a revision asks each active holder once (`asked` in the answer) and tells them (`grc.policy_to_acknowledge`); the
  asks of earlier revisions are withdrawn. Acknowledging closes the person's ask; retiring withdraws the open ones.
  "Who has not acknowledged the current revision of a policy?", which the assistant suggested and nothing could
  answer, is now the list of Attestations still Due.
- **Joiners, leavers, reminders.** Upkeep asks people who joined the role since, releases those who left it,
  reminds once before the day (`grc.policy_reminder`, the reminder days of Governance Settings) and marks late asks
  overdue.
- **One acknowledgement per revision,** now also a unique key, as is one ask per person and revision.
- A reader sees their own asks on the home page; a Risk Manager sees who has not acknowledged.

## 0.3.0

Needs the same platform as 0.2.0. Package `grc` 0.2.0: new fields (`GrcSettings.reminder_days`, a hidden
`reminded_for` on Risk Acceptance and Finding) added by the platform's schema sync; an existing workspace reads an
empty `reminder_days` as 14. `ui/dist` rebuilt for the new setting's words.

- **A decided acceptance keeps its terms.** Once an acceptance was accepted (or rejected, revoked, expired), a Risk
  Manager could still change its expiry day, its reason or its risk, so the approver's decision covered something
  they never saw. Now nobody can, an administrator included; propose a new acceptance. An acceptance whose day has
  passed is no longer accepted.
- **Expiry keeps a treatment chosen since.** An expired acceptance set its risk to Open even when the treatment had
  been changed to Mitigate, Avoid or Transfer meanwhile. It now reopens only a risk still treated as Accept.
- **People are told.** The risk's owner and the approver hear (message templates `grc.acceptance_expiring`,
  `grc.acceptance_expired`) the reminder days before an acceptance ends and when it has; a finding's owner
  (`grc.finding_due`, `grc.finding_overdue`) before it is due and when it goes overdue. Each once, even from two
  upkeeps at once: the rows are held and the marker written in the same transaction.
- **People's data and hand-over.** `personal_data` for its seven entities with addresses, and `handover` of a
  leaver's risks, open controls, open findings and live policies.
- **Every action says what done means** (`contract.completion` on all six).

## 0.2.0

Needs Ferrum 0.4.0 (apps' upkeep runs one workspace at a time, on whichever replica is free). No database or interface change.

**Upkeep is one workspace's.** `maintenance(k, tenant)` and `maintenance_on(k, tenant, today)` expire acceptances, keep controls' standing current and mark overdue findings in the one workspace the platform hands them; the list of workspaces and the installation check are the platform's.

## 0.1.18

Server only. Needs the same platform as 0.1.17. No interface or database change.

- **"Today" is the workspace's day.** A policy published and an acceptance decided were dated on the UTC day; a control
  test was refused as in the future, and a draft acceptance as expired, against the UTC day; whether an acceptance
  still holds a risk was judged on the database's day, which is UTC; and the upkeep expired acceptances, marked
  controls stale and findings overdue on the UTC day. A workspace east of UTC met yesterday's rules in the first hours
  of its day, one west of UTC tomorrow's in its evenings. All are on the workspace's own day now.

## 0.1.17

Needs the same platform as 0.1.16. No database change. Interface only, `ui/dist` rebuilt with Ferrum-Frontend `06bd1a2`.

- The two routes to the screens apps no longer have (`apps/:app/settings`, `x/:app/:page`) are gone.
- The page starts through the frontend's `mountApp`, which keeps lists fresh for 30 seconds (Governance and Risk said 5); the
  interface lint has no baseline file any more.

## 0.1.16

Rebuilt with Ferrum-Frontend 9e7190c, the design system as tuned after the landed build was reviewed. The left menu's icons are chosen so that none repeats on more than three rows and each fits its row; their drawings load beside the first page instead of inside it, so the page starts lighter; a row that scrolls sideways fades at the edge where there is more, in every browser and with reduced motion; a printed record leaves out empty fields and keeps its totals with the table; menus and popovers sit inside the page's landmarks for assistive technology; a selection bar folds what does not fit into More on a narrow screen. Nothing else changes.

## 0.1.15

The interface follows the upgraded design system, rebuilt with Ferrum-Frontend 76c4fad. Text uses the kit's type roles (nothing under 12px) and controls its height tokens; loading shows skeletons shaped like what is coming; empty, no matches, denied, offline and failed are told apart; status colours come from stored state ids. The interface check now runs the UI lint against an empty baseline. The home is rebuilt on the kit's work-home pattern: one page title, the main action as a button, queues with their counts, status at its natural width; its other own pages follow the same anatomy.

## 0.1.14

Rebuilt with Ferrum-Frontend 43d7779: the names of its models, fields and manifest in Arabic and Hindi (124 each in ui/src/locales/names, which the platform serves to every page of the workspace, so a record's labels, the launcher and the bar read in the person's language). Translated by the model, to be reviewed by native speakers.

## 0.1.13

The assistant knows what its records mean in its pages (contributes.shell.assistant): their states, what counts and where figures come from, with questions it suggests asking there.

## 0.1.12

Rebuilt with Ferrum-Frontend 389b2af: its own words carry built-in Arabic and Hindi (17 words each, ui/src/locales, translated by the model and to be reviewed by native speakers), fetched for the page's language only. The labels it keeps in objects, its dialogs, its page titles and the words it keeps in variables go through t() as well, and the names and sizes it shows as they are keep their order right to left. Its pages are drawn once their words are in, and its entry carries only the parts of the kit it uses.

## 0.1.11

Rebuilt with Ferrum-Frontend 1f5981d: an action's link, code or token shown once is kept in a dialog to copy, and on a page that reads right to left, English left untranslated keeps its own order. Its own words go through the kit's t() (13 places), so a workspace's own words for its language reach them, and Admin, Interface words lists them under it (dist/words.json).

## 0.1.10

Rebuilt with Ferrum-Frontend 8a1c2e7: a workspace's own words for its interface (Admin, Interface words) reach its pages as they load; an attachment field that holds a picture shows it; and a value another record already has is said so, where the form said the record had been changed by someone else.

## 0.1.9

Rebuilt with Ferrum-Frontend 9d80f4f: right to left, its pages mirror as they read (icons that point along the line, margins and alignment by the line's start and end, arrow keys along it), and the records pages' words are in Arabic and Hindi.

## 0.1.8

Rebuilt with Ferrum-Frontend 204b713: a new record's box whose default is 1 shows ticked, as it is saved.

## 0.1.7

Rebuilt with Ferrum-Frontend 6cfda39: an action's dialog says every refusal, the errors on what the action made (another record's rows) among them, and an action with parameters and a confirmation asks once.

## 0.1.6

Rebuilt with Ferrum-Frontend b39fffb: its pages show times on a person's own clock when they chose one on their Account page, while today and due dates stay on the workspace's day.

## 0.1.5

Rebuilt with Ferrum-Frontend d350579: its pages show times on the workspace's clock, naming the zone when it is not the browser's, a draft numbered on submit is headed as a draft, and a record of an app that is not installed says so.

## 0.1.4

Rebuilt with Ferrum-Frontend 20d08e5: a record page reads an empty number or check as the server does, so an action whose condition needs one shows, and a workspace's settings open as their one record.

## 0.1.3

Rebuilt with Ferrum-Frontend ae13c69: in a workflow state that names what may change, the other fields show read-only, and the fields the state needs show required.

## 0.1.2

Rebuilt with Ferrum-Frontend daeadda: after an action runs, a record page shows what the action said it did rather than only that it is done.

## 0.1.1

Rebuilt with Ferrum-Frontend 89b7cc7: a field's label names its control for assistive technology, and a record whose title is a link shows that record's title, not its id.

## 0.1.0

Governance and risk (FERRUM-ECOSYSTEM-014).

- A risk register: inherent, current and residual scores on a five-by-five matrix, levels and
  treatment; mitigation names its controls.
- Risk acceptances for risks above the tolerance, approved by a Risk Approver who does not own the
  risk, expiring or revoked back to open.
- Controls tested with evidence; effective while their latest test is effective and current.
- Policies published by revision and acknowledged once a revision by each person.
- Findings overdue when late, and closed saying how.
- Its own interface at `/grc/`: the register.
