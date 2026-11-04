# Provenance

## CISO Assistant

- Source: [intuitem/ciso-assistant-community](https://github.com/intuitem/ciso-assistant-community),
  commit e1dbc3d, `backend/core/models.py` (`RiskScenario`, `AppliedControl`, `RiskAcceptance`).
- Licence: GNU Affero General Public License v3, for everything outside the repository's
  `enterprise/` directory, which was not read. This app is under the same licence.
- What was taken, as designs rather than code:
  - a risk's inherent, current and residual likelihood and impact, and its treatment options
    (open, mitigate, accept, avoid, transfer);
  - risk acceptances with an approver, an expiry, and the states accepted, rejected and revoked;
  - controls applied to risks.
- Its own: the five-by-five scores and levels, the tolerance, the checks between the three scores,
  control tests and their staleness, policy revisions and acknowledgements, findings, and all the
  code.

The copy read is in `ERP/referance/grc/ciso-assistant` on the machine this was written on (sparse:
`backend/core`).
