import { expect, it } from "vitest";

import { analyzeJavaScriptArtifactFiles } from "./JavaScriptArtifactAnalysis.js";

const HASH = "a".repeat(64);

it("reports the locations of inline HTML scripts that are not analyzed", () => {
  const html = [
    "<html><body>",
    "<script>function startGame() {}</script>",
    '<script type="module">import { x } from "./mod.js";</script>',
    "</body></html>",
  ].join("\n");
  const analysis = analyzeJavaScriptArtifactFiles({
    files: [
      {
        path: "www/index.html",
        container_sha256: HASH,
        sha256: HASH,
        bytes: Buffer.byteLength(html),
        inventory_artifact_id: "index.html",
        kind: "html",
        unpacked: false,
        text: { included: true, value: html },
      },
    ],
    containers: [],
    text_bytes_read: Buffer.byteLength(html),
    invalid_utf8_files: 0,
  });

  expect(analysis.html_scripts).toEqual([]);
  expect(analysis.omitted_inline_scripts).toBe(2);
  expect(analysis.limitations).toContain(
    "Inline script elements in www/index.html were not analyzed (source locations: 2:1, 3:1).",
  );
});
