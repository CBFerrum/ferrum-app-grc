// The register: risks by level (critical first), controls no longer effective, open findings, and
// published policies. Each opens its record, where a policy is acknowledged.

import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { api, docPath, t, isolate } from "@ferrum/client";
import { Badge, ErrorState, ListSkeleton, useShellTitle } from "@ferrum/kit";

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
  if (q.isPending) return <ListSkeleton className="np-page" />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  return (
    <div className="np-page">
      <header className="row" style={{ justifyContent: "space-between" }}>
        <h2>{t("The register")}</h2>
        <Link to="/e/Risk/new">{t("New risk")}</Link>
      </header>
      <div className="np-columns">
        <section className="card card-pad stack" aria-label={t("Risks")}>
          <h3>{t("Risks ({length})", { length: q.data.risks.length })}</h3>
          <ul className="stack">
            {q.data.risks.map((r) => (
              <li key={r.id}>
                <Badge tone={TONE[String(r.level)] ?? "neutral"}>{isolate(`${String(r.level ?? "")} ${String(r.current_score ?? "")}`)}</Badge> <Link to={`/e/Risk/${r.id}`}>{isolate(String(r.title))}</Link> · {isolate(String(r.treatment ?? ""))}
              </li>
            ))}
          </ul>
        </section>
        <section className="card card-pad stack" aria-label={t("Controls to test")}>
          <h3>{t("Controls to test ({length})", { length: q.data.controls.length })}</h3>
          <ul className="stack">
            {q.data.controls.map((c) => (
              <li key={c.id}>
                <Link to={`/e/Control/${c.id}`}>{isolate(String(c.control_name))}</Link> {c.last_tested_on ? t("· last {value}", { value: String(c.last_tested_on) }) : t("· never tested")}
              </li>
            ))}
          </ul>
        </section>
        <section className="card card-pad stack" aria-label={t("Open findings")}>
          <h3>{t("Open findings ({length})", { length: q.data.findings.length })}</h3>
          <ul className="stack">
            {q.data.findings.map((f) => (
              <li key={f.id}>
                <Link to={`/e/Finding/${f.id}`}>{t("{value} · {value2} · due {value3}", { value: String(f.number ?? ""), value2: String(f.title), value3: String(f.due_on ?? "") })}</Link> {f.overdue ? <Badge tone="red">{t("Overdue")}</Badge> : null}
              </li>
            ))}
          </ul>
        </section>
        <section className="card card-pad stack" aria-label={t("Policies")}>
          <h3>{t("Policies ({length})", { length: q.data.policies.length })}</h3>
          <ul className="stack">
            {q.data.policies.map((p) => (
              <li key={p.id}>
                <Link to={`/e/Policy/${p.id}`}>{t("{value} · revision {value2}", { value: String(p.title), value2: String(p.revision ?? "") })}</Link>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}
