import { describe, expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

/** Every specifier the static analysis recorded as a loader call. */
const requireSpecifiers = (source: string): readonly unknown[] =>
  analyzeJavaScriptStaticSource(source)
    .references.filter((reference) => reference.kind === "require")
    .map((reference) => (reference as { specifier?: unknown }).specifier);

describe("static require loader calls", () => {
  it("records a require call that no binding shadows", () => {
    expect(requireSpecifiers('const loaded = require("./real.cjs");')).toEqual([
      "./real.cjs",
    ]);
  });

  it("ignores a require call that a local binding shadows", () => {
    expect(
      requireSpecifiers(`
        function run(require) {
          return require("./ghost.cjs");
        }
        console.log(run(() => "local"));
      `),
    ).toEqual([]);
  });
});
