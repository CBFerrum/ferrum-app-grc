// The register: risks by level (critical first), controls no longer effective, open findings, policies
// someone is asked to acknowledge, and published policies. Each opens its record, where a policy is acknowledged.

import { useQuery } from "@tanstack/react-query";
import { api, docPath, formatValue, t, isolate } from "@ferrum/client";
import { can, useEntityMeta } from "@ferrum/records";
import { Badge, ButtonLink, HomeSkeleton, LoadFailed, PageHead, PageStack, Queue, QueueGrid, QueueItem, type Tone, useShellTitle } from "@ferrum/kit";

export interface Row {
  id: string;
  [k: string]: unknown;
}

const rows = (entity: string, filters: unknown[], extra: Record<string, string | number> = {}) =>
  api.get<{ rows: Row[] }>(docPath(entity), { filters: JSON.stringify(filters), limit: 500, ...extra }).then((r) => r.rows);

const ORDER = ["Critical", "High", "Medium", "Low"];

/** Risks, the worst first, then by score. */
export function worstFirst(list: Row[]): Row[] {
  const rank = (r: Row) => ORDER.indexOf(String(r.level ?? "Low"));
  return [...list].sort((a, b) => rank(a) - rank(b) || Number(b.current_score ?? 0) - Number(a.current_score ?? 0));
}

/** Incidents with a notice overdue first, the rest as they came. */
export function overdueFirst(list: Row[]): Row[] {
  return [...list].sort((a, b) => Number(Boolean(b.notice_overdue)) - Number(Boolean(a.notice_overdue)));
}

const TONE: Record<string, Tone> = { Critical: "red", High: "amber", Medium: "blue", Low: "neutral" };

/** The tone of a risk's level mark, from its stored id; any other value is neutral. */
export const levelTone = (level: unknown) => (typeof level === "string" && Object.prototype.hasOwnProperty.call(TONE, level) ? TONE[level] : "neutral");

/** A day as the person reads it ("20 Nov 2026"); empty when there is none. */
const day = (v: unknown) => formatValue({ type: "date" }, v);

/** The queues show this many rows each; the rest is "and N more", linking to the list. */
const LIMIT = 5;

export function Home() {
  useShellTitle(t("Governance and Risk"));
  const manages = can(useEntityMeta("Policy").data?.permissions, "write");
  const q = useQuery({
    queryKey: ["grc", "register"],
    queryFn: async () => {
      const [risks, controls, findings, policies, asks, assessments, incidents, plans] = await Promise.all([
        rows("Risk", []),
        rows("Control", [["status", "eq", "In Place"], ["effective", "eq", false]]),
        rows("Finding", [["status", "!=", "Closed"]], { sort: "due_on asc" }),
        rows("Policy", [["status", "eq", "Published"]], { sort: "title asc" }),
        // A reader is served their own asks; a Risk Manager everyone's.
        rows("PolicyAttestation", [["status", "eq", "Due"]], { sort: "due_on asc", titles: "true" }),
        rows("ComplianceAssessment", [["status", "eq", "In Progress"]], { sort: "created_at desc", titles: "true" }),
        rows("Incident", [["status", "!=", "Resolved"]], { sort: "detected_at desc" }),
        rows("ContinuityPlan", [["status", "eq", "In Force"], ["current", "eq", false]], { sort: "plan_name asc" }),
      ]);
      return { risks: worstFirst(risks), controls, findings, policies, asks, assessments, incidents: overdueFirst(incidents), plans };
    },
  });
  const create = (
    <ButtonLink to="/e/Risk/new" variant="primary" icon="plus">
      {t("New risk")}
    </ButtonLink>
  );
  if (q.isPending) return (
    <PageStack>
      <PageHead title={t("The register")} />
      <HomeSkeleton queues={6} />
    </PageStack>
  );
  if (q.isError) return (
    <PageStack>
      <PageHead title={t("The register")} actions={create} />
      <LoadFailed error={q.error} onRetry={() => void q.refetch()} />
    </PageStack>
  );
  const { risks, controls, policies, asks, assessments, incidents, plans } = q.data;
  // What is late comes before what is merely due.
  const findings = [...q.data.findings].sort((a, b) => Number(Boolean(b.overdue)) - Number(Boolean(a.overdue)));
  const summary = [findings.length && t("{n} open findings", { n: findings.length }), controls.length && t("{n} controls to test", { n: controls.length })].filter(Boolean).join(" · ");
  return (
    <PageStack>
      <PageHead title={t("The register")} description={summary ? isolate(summary) : undefined} actions={create} />
      <QueueGrid>
        {incidents.length > 0 && (
          <Queue title={t("Incidents")} count={incidents.length} tone={incidents.some((i) => i.notice_overdue) ? "attention" : "default"} more={{ to: "/e/Incident", count: incidents.length - LIMIT }}>
            {incidents.slice(0, LIMIT).map((i) => (
              <QueueItem
                key={i.id}
                to={`/e/Incident/${i.id}`}
                title={isolate(String(i.title))}
                meta={i.detected_at ? t("detected {day}", { day: day(String(i.detected_at).slice(0, 10)) }) : undefined}
                trailing={i.notice_overdue ? <Badge tone="red">{t("Notice overdue")}</Badge> : null}
              />
            ))}
          </Queue>
        )}
        <Queue title={t("Open findings")} count={findings.length} tone={findings.some((f) => f.overdue) ? "attention" : "default"} more={{ to: "/e/Finding", count: findings.length - LIMIT }}>
          {findings.slice(0, LIMIT).map((f) => (
            <QueueItem key={f.id} to={`/e/Finding/${f.id}`} title={isolate(String(f.title))} meta={isolate([String(f.number ?? ""), f.due_on ? t("due {day}", { day: day(f.due_on) }) : ""].filter(Boolean).join(" · "))} trailing={f.overdue ? <Badge tone="red">{t("Overdue")}</Badge> : null} />
          ))}
        </Queue>
        <Queue title={t("Controls to test")} count={controls.length} more={{ to: "/e/Control", count: controls.length - LIMIT }}>
          {controls.slice(0, LIMIT).map((c) => (
            <QueueItem key={c.id} to={`/e/Control/${c.id}`} title={isolate(String(c.control_name))} meta={c.last_tested_on ? t("last tested {day}", { day: day(c.last_tested_on) }) : t("never tested")} />
          ))}
        </Queue>
        {plans.length > 0 && (
          <Queue title={t("Plans to test")} count={plans.length} more={{ to: "/e/ContinuityPlan", count: plans.length - LIMIT }}>
            {plans.slice(0, LIMIT).map((p) => (
              <QueueItem key={p.id} to={`/e/ContinuityPlan/${p.id}`} title={isolate(String(p.plan_name))} meta={p.last_tested_on ? t("last tested {day}", { day: day(p.last_tested_on) }) : t("never tested")} />
            ))}
          </Queue>
        )}
        <Queue title={t("Risks")} count={risks.length} tone={risks.some((r) => r.level === "Critical") ? "attention" : "default"} more={{ to: "/e/Risk", count: risks.length - LIMIT }}>
          {risks.slice(0, LIMIT).map((r) => (
            <QueueItem key={r.id} to={`/e/Risk/${r.id}`} title={isolate(String(r.title))} meta={isolate(String(r.treatment ?? ""))} trailing={<Badge tone={levelTone(r.level)}>{isolate(`${String(r.level ?? "")} ${String(r.current_score ?? "")}`)}</Badge>} />
          ))}
        </Queue>
        {asks.length > 0 && (
          <Queue title={manages ? t("Awaiting acknowledgement") : t("To acknowledge")} count={asks.length} tone={asks.some((a) => a.overdue) ? "attention" : "default"} more={{ to: "/e/PolicyAttestation", count: asks.length - LIMIT }}>
            {asks.slice(0, LIMIT).map((a) => (
              <QueueItem
                key={a.id}
                to={`/e/Policy/${String(a.policy)}`}
                title={isolate(String((a._titles as Record<string, unknown> | undefined)?.policy ?? a.policy))}
                meta={isolate([manages ? String(a.person ?? "") : "", a.due_on ? t("due {day}", { day: day(a.due_on) }) : ""].filter(Boolean).join(" · "))}
                trailing={a.overdue ? <Badge tone="red">{t("Overdue")}</Badge> : null}
              />
            ))}
          </Queue>
        )}
        {assessments.length > 0 && (
          <Queue title={t("Assessments")} count={assessments.length} more={{ to: "/e/ComplianceAssessment", count: assessments.length - LIMIT }}>
            {assessments.slice(0, LIMIT).map((a) => (
              <QueueItem
                key={a.id}
                to={`/e/ComplianceAssessment/${a.id}`}
                title={isolate(String(a.title))}
                meta={isolate(String((a._titles as Record<string, unknown> | undefined)?.framework ?? ""))}
                trailing={a.coverage == null ? null : <Badge tone="neutral">{t("{n} %", { n: String(Number(a.coverage)) })}</Badge>}
              />
            ))}
          </Queue>
        )}
        <Queue title={t("Policies")} count={policies.length} more={{ to: "/e/Policy", count: policies.length - LIMIT }}>
          {policies.slice(0, LIMIT).map((p) => (
            <QueueItem key={p.id} to={`/e/Policy/${p.id}`} title={isolate(String(p.title))} meta={p.revision ? t("revision {revision}", { revision: String(p.revision) }) : undefined} />
          ))}
        </Queue>
      </QueueGrid>
    </PageStack>
  );
}
