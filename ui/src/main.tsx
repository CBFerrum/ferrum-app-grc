// Governance and Risk's own interface at /grc/: the risk register by level, controls due a test and
// policies to acknowledge, with every record in the records frame's lists and forms.

import { mountApp, setFrameMode } from "@ferrum/records/frame";
import { GRC_PACKAGES, routes } from "./routes";
import "./styles.css";

setFrameMode("app", GRC_PACKAGES);

mountApp({
  route: "grc",
  catalogs: { ar: () => import("./locales/ar.json"), hi: () => import("./locales/hi.json") },
  routes,
});
