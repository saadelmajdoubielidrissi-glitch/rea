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

  it("records a member loader call", () => {
    expect(
      requireSpecifiers('const loaded = module.require("./member.cjs");'),
    ).toEqual(["./member.cjs"]);
  });

  it("records a loader a createRequire binding provides", () => {
    expect(
      requireSpecifiers(`
        import { createRequire } from "node:module";
        const require = createRequire(import.meta.url);
        const loaded = require("./created.cjs");
      `),
    ).toEqual(["./created.cjs"]);
  });

  it("follows an aliased createRequire import from node:module", () => {
    expect(
      requireSpecifiers(`
        import { createRequire as makeRequire } from "node:module";
        const require = makeRequire(import.meta.url);
        const loaded = require("./aliased.cjs");
      `),
    ).toEqual(["./aliased.cjs"]);
  });

  it("does not treat a local createRequire function as Node's factory", () => {
    expect(
      requireSpecifiers(`
        function createRequire() { return () => "local"; }
        const require = createRequire();
        const loaded = require("./ghost.cjs");
      `),
    ).toEqual([]);
  });

  it("keeps the CommonJS wrapper loader separate from globalThis.require", () => {
    expect(
      requireSpecifiers(`
        globalThis.require = shim;
        const loaded = require("./wrapper.cjs");
      `),
    ).toEqual(["./wrapper.cjs"]);
  });

  it("keeps an uninitialized top-level var redeclaration of the wrapper loader", () => {
    expect(requireSpecifiers('var require; require("./wrapper.cjs");')).toEqual(
      ["./wrapper.cjs"],
    );
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
