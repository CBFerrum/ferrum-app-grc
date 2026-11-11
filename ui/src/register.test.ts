import { describe, expect, it } from "vitest";
import { levelTone, worstFirst } from "./Home";

describe("the register", () => {
  it("puts the worst risks first, then the highest scores", () => {
    const l = worstFirst([
      { id: "m", level: "Medium", current_score: 6 },
      { id: "c", level: "Critical", current_score: 20 },
      { id: "h2", level: "High", current_score: 12 },
      { id: "h1", level: "High", current_score: 15 },
    ]);
    expect(l.map((r) => r.id)).toEqual(["c", "h1", "h2", "m"]);
  });

  it("keeps a level's tone from its stored id", () => {
    expect(["Critical", "High", "Medium", "Low", "Severe", "", null].map(levelTone)).toEqual(["red", "amber", "blue", "neutral", "neutral", "neutral", "neutral"]);
    expect(levelTone("constructor")).toBe("neutral");
  });
});
