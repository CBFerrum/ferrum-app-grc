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
  - controls applied to risks;
  - frameworks and their requirement nodes in a tree, and controls mapped to requirements
    (`Framework`, `RequirementNode`, read at the same file's lines 3888 and 4176 in the reference checkout).
- Its own: the matrix as settings, the tolerance, the checks between the three scores,
  control tests and their staleness, policy revisions and acknowledgements, findings, and all the
  code.
