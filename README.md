# Governance and Risk

Governance, risk and compliance for [Ferrum](https://github.com/CBFerrum/Ferrum):
- a risk register scored on a five-by-five matrix, with treatment and acceptance;
- controls, tested with their evidence;
- policies published by revision and acknowledged;
- findings, with their owners and days.

| | |
|---|---|
| 🛡️ App | `grc`, native, in the server |
| 🧩 Package | `grc` (needs only the platform's core) |
| 🖥️ Interface | its own, at `/grc/`: risks by level, controls to test, open findings and policies, and the records |
| 🔐 Roles | Risk Manager, Risk Approver, Policy Reader |
| 📜 Licence | AGPL-3.0-only |

No framework's text (ISO, SOC 2, NIST) is included; a control names the requirements it answers by
their identifiers. No certification is claimed.

## Highlights

- **Three scores.** A risk is scored before controls (inherent), with them (current) and as
  targeted (residual), each likelihood times impact out of 25. Controls never make it worse, nor
  does the target. Its level (low, medium, high, critical) is the current score's.
- **Treatment.** Mitigating names the controls that do it. A risk above the tolerance is accepted
  only with an approved acceptance.
- **Acceptances.** An acceptance says why and until when. A Risk Approver who does not own the
  risk approves it, rejects it or revokes it. Once it expires or is revoked, the risk is open again
  (after CISO Assistant's risk acceptances).
- **Controls and tests.** A control is tested once it is in place, on a day not in the future. An
  effective result needs its evidence. A control is effective while its latest test by day was
  effective and is still current; upkeep marks stale ones as needing a test.
- **Policies.** Publishing new text puts a policy at its next revision, keeping the text as
  published. Each person acknowledges each revision once. A retired policy is no longer read.
- **Findings.** A finding past its day is overdue. Closed, it says how it was fixed.

## Develop

```bash
cargo test                       # needs FERRUM_GRC_TEST_DATABASE_URL's database
cd ui && npm run build && npm run check
```

`tests/grc_it.rs` walks a security programme:
- controls tested, and their standing going stale;
- risks scored, and refused when they make no sense;
- an acceptance approved, expired, revoked and rejected;
- a policy published twice and acknowledged;
- findings overdue and closed;
- who may do what.

## Not yet

- Framework libraries mapping controls to requirements, and compliance assessments of them.
- Assets, threats and vulnerabilities on risks, and risk matrices other than five by five.
- Several approvers for an acceptance, and reminders before it expires.
- Evidence collected automatically from other apps.

## Changelog

| Version | Highlights |
|---|---|
| **0.1.3** | Rebuilt with Ferrum-Frontend 00dea07: a workflow state's kept fields are read-only, its needed ones required. |
| **0.1.2** | Rebuilt with Ferrum-Frontend daeadda: actions say what they did. |
| **0.1.1** | Rebuilt with Ferrum-Frontend 80ff179: labels name their fields, and linked titles show their titles. |
| **0.1.0** | Risks scored on a matrix with their treatment and acceptance, controls tested with evidence, policies acknowledged by revision, and findings (FERRUM-ECOSYSTEM-014). |

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
