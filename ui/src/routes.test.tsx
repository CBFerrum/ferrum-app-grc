// @vitest-environment jsdom
// The app's real route table, mounted: a Policy Reader's home lists the policies they are asked to acknowledge,
// and a Risk Manager's names who has not. me.json is the shape a running server answers GET /api/auth/me with.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setFrameMode } from "@ferrum/records/frame";
import me from "./fixtures/me.json";
import { GRC_PACKAGES, routes } from "./routes";

// The first test loads the whole page's modules: on a machine busy building, more than vitest's five seconds.
vi.setConfig({ testTimeout: 30000 });

let write = "none";
/** Policy's description as the server gives it, its fields left out: the home reads only its rights. */
const policyMeta = (w: string) => ({
  name: "Policy", label: "Policy", label_plural: "Policies", kind: "master", module: "grc", package: "grc", title_field: "title", custom: false, description: null, icon: null,
  actions: [], approvals: {}, children: {}, company_scoped: false, fields: [], form: [], linked_from: [], list: { columns: [], sort: "title asc" }, mergeable: false,
  numbering: null, published_lists: [], rules: [], search_fields: [], submittable: false, targets: [], workflow: null,
  permissions: { read: "all", write: w, create: w, delete: "none", export: "none", import: "none", submit: "none", cancel: "none", actions: [] },
});
const asks = [
  { id: "a1", policy: "p1", _titles: { policy: "Handbook" }, person: "pat@secure.test", revision: 2, due_on: "2026-12-18", status: "Due", overdue: false },
  { id: "a2", policy: "p2", _titles: { policy: "Clean desk" }, person: "pat@secure.test", revision: 1, due_on: "2026-11-10", status: "Due", overdue: true },
];

const assessments = [{ id: "c1", title: "2026 assessment", framework: "f1", _titles: { framework: "Our baseline" }, status: "In Progress", coverage: "66.67" }];

beforeEach(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  (globalThis as { matchMedia?: unknown }).matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const path = new URL(String(input instanceof Request ? input.url : input), "http://localhost").pathname;
      const json = (b: unknown) => new Response(JSON.stringify(b), { status: 200, headers: { "content-type": "application/json" } });
      if (path === "/api/auth/me") return json(me);
      if (path === "/api/meta") return json({ entities: [], modules: [], reports: [] });
      if (path === "/api/meta/Policy") return json(policyMeta(write));
      if (path === "/api/v1/PolicyAttestation") return json({ rows: asks, total: asks.length });
      if (path === "/api/v1/ComplianceAssessment") return json({ rows: assessments, total: assessments.length });
      return json({ rows: [], total: 0 });
    }),
  );
  setFrameMode("app", GRC_PACKAGES);
});
afterEach(() => vi.unstubAllGlobals());

async function home() {
  const host = document.createElement("div");
  document.body.append(host);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const root = createRoot(host);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={createMemoryRouter(routes, { initialEntries: ["/"] })} />
      </QueryClientProvider>,
    );
  });
  // Until the page has loaded (its Policies queue is drawn), at most ten seconds on a busy machine.
  for (let i = 0; i < 400 && !(host.textContent ?? "").includes("Policies"); i++) await act(async () => void (await new Promise((r) => setTimeout(r, 25))));
  const text = host.textContent ?? "";
  const links = [...host.querySelectorAll("a")].map((a) => a.getAttribute("href"));
  await act(async () => root.unmount());
  host.remove();
  return { text, links };
}

describe("the home", () => {
  it("a reader's home lists what they owe", async () => {
    write = "none";
    const { text, links } = await home();
    expect(text).toContain("To acknowledge");
    expect(text).toContain("Handbook");
    expect(text).toContain("Clean desk");
    expect(text).toContain("Overdue");
    expect(links).toContain("/e/Policy/p1");
  });

  it("the home page shows assessments in progress with their coverage", async () => {
    write = "all";
    const { text, links } = await home();
    expect(text).toContain("Assessments");
    expect(text).toContain("2026 assessment");
    expect(text).toContain("Our baseline");
    expect(text).toContain("66.67 %");
    expect(links).toContain("/e/ComplianceAssessment/c1");
  });

  it("a Risk Manager's home names who has not acknowledged", async () => {
    write = "all";
    const { text } = await home();
    expect(text).toContain("Awaiting acknowledgement");
    expect(text).toContain("pat@secure.test");
  });
});
