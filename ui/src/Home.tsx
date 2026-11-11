// The register: risks by level (critical first), controls no longer effective, open findings, and
// published policies. Each opens its record, where a policy is acknowledged.

import { useQuery } from "@tanstack/react-query";
import { api, docPath, formatValue, t, isolate } from "@ferrum/client";
import { Badge, ButtonLink, HomeSkeleton, LoadFailed, PageHead, Queue, QueueGrid, QueueItem, useShellTitle } from "@ferrum/kit";

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

const TONE: Record<string, "red" | "amber" | "blue" | "neutral"> = { Critical: "red", High: "amber", Medium: "blue", Low: "neutral" };

/** The tone of a risk's level mark, from its stored id; any other value is neutral. */
export const levelTone = (level: unknown) => (typeof level === "string" && Object.prototype.hasOwnProperty.call(TONE, level) ? TONE[level] : "neutral");

/** A day as the person reads it ("20 Nov 2026"); empty when there is none. */
const day = (v: unknown) => formatValue({ type: "date" }, v);

/** The queues show this many rows each; the rest is "and N more", linking to the list. */
const LIMIT = 5;

export function Home() {
  useShellTitle(t("Governance and Risk"));
  const q = useQuery({
    queryKey: ["grc", "register"],
    queryFn: async () => {
      const [risks, controls, findings, policies] = await Promise.all([
        rows("Risk", []),
        rows("Control", [["status", "eq", "In Place"], ["effective", "eq", false]]),
        rows("Finding", [["status", "!=", "Closed"]], { sort: "due_on asc" }),
        rows("Policy", [["status", "eq", "Published"]], { sort: "title asc" }),
      ]);
      return { risks: worstFirst(risks), controls, findings, policies };
    },
  });
  const create = (
    <ButtonLink to="/e/Risk/new" variant="primary" icon="plus">
      {t("New risk")}
    </ButtonLink>
  );
  if (q.isPending) return (
    <>
      <PageHead title={t("The register")} />
      <HomeSkeleton queues={4} />
    </>
  );
  if (q.isError) return (
    <>
      <PageHead title={t("The register")} actions={create} />
      <LoadFailed error={q.error} onRetry={() => void q.refetch()} />
    </>
  );
  const { risks, controls, policies } = q.data;
  // What is late comes before what is merely due.
  const findings = [...q.data.findings].sort((a, b) => Number(Boolean(b.overdue)) - Number(Boolean(a.overdue)));
  return (
    <>
      <PageHead title={t("The register")} description={findings.length + controls.length > 0 ? t("{findings} open findings · {controls} controls to test", { findings: findings.length, controls: controls.length }) : undefined} actions={create} />
      <QueueGrid>
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
        <Queue title={t("Risks")} count={risks.length} tone={risks.some((r) => r.level === "Critical") ? "attention" : "default"} more={{ to: "/e/Risk", count: risks.length - LIMIT }}>
          {risks.slice(0, LIMIT).map((r) => (
            <QueueItem key={r.id} to={`/e/Risk/${r.id}`} title={isolate(String(r.title))} meta={isolate(String(r.treatment ?? ""))} trailing={<Badge tone={levelTone(r.level)}>{isolate(`${String(r.level ?? "")} ${String(r.current_score ?? "")}`)}</Badge>} />
          ))}
        </Queue>
        <Queue title={t("Policies")} count={policies.length} more={{ to: "/e/Policy", count: policies.length - LIMIT }}>
          {policies.slice(0, LIMIT).map((p) => (
            <QueueItem key={p.id} to={`/e/Policy/${p.id}`} title={isolate(String(p.title))} meta={p.revision ? t("revision {revision}", { revision: String(p.revision) }) : undefined} />
          ))}
        </Queue>
      </QueueGrid>
    </>
  );
}
