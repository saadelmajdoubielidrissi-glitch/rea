import { createServer } from "node:http";
import { writeFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { expect, onTestFinished } from "vitest";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { historicalHar } from "../../fixtures/historicalHar.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

cliTest(
  "projects query names from recorded local requests through compiled CLI and retained MCP Evidence",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-query-names-");
    const recorded: string[] = [];
    const server = createServer((request, response) => {
      if (request.url === undefined) throw new Error("Expected request target");
      recorded.push(request.url);
      response.setHeader("Content-Type", "application/json");
      response.end("{}");
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    onTestFinished(
      () =>
        new Promise<void>((resolve, reject) => {
          server.closeAllConnections();
          server.close((error) => (error ? reject(error) : resolve()));
        }),
    );
    const address = server.address();
    if (address === null || typeof address === "string")
      throw new Error("Expected local listener");
    const origin = `http://127.0.0.1:${address.port}`;
    for (const target of [
      "/items/1?category=QUERY_VALUE_ONLY&repeat=1&repeat=2&plus%2Bname=3&space+name=4",
      "/items/2?category=QUERY_VALUE_ONLY&page=1&repeat=3&space%20name=5",
    ]) {
      const response = await fetch(origin + target);
      await response.text();
    }
    const har = historicalHar();
    const prototype = har.log.entries[0]!;
    har.log.creator.name = "local-http-recording";
    har.log.entries = recorded.map((target) => ({
      ...prototype,
      request: {
        ...prototype.request,
        url: origin + target,
        httpVersion: "HTTP/1.1",
      },
      response: {
        ...prototype.response,
        httpVersion: "HTTP/1.1",
        content: { size: 2, mimeType: "application/json", text: "{}" },
        bodySize: 2,
      },
    }));
    const capturePath = join(root, "requests.har");
    await writeFile(capturePath, JSON.stringify(har));
    const captured = await cli.run({
      arguments: ["inspect-web-network-capture", capturePath, "har", "--json"],
    });
    expect(captured.exitCode, captured.stdout + captured.stderr).toBe(0);
    const parent = parseEvidence(captured.json);
    const { call } = await connectLocalToolsMcp();
    const mcpCapture = await call("inspect_web_network_capture", {
      capture_path: capturePath,
      format: "har",
    });
    expect(mcpCapture.isError).not.toBe(true);
    const retained = parseEvidence(mcpCapture.structuredContent);
    await unlink(capturePath);
    const view = { kind: "api-surface", include_query_parameter_names: true };
    const input = join(root, "view.json");
    await writeFile(
      input,
      JSON.stringify({ source: { kind: "inline", evidence: parent }, view }),
    );
    const projected = await cli.run({
      arguments: ["inspect-analysis-view", input, "--json"],
    });
    expect(projected.exitCode, projected.stdout + projected.stderr).toBe(0);
    const evidence = parseEvidence(projected.json);
    const mcpView = await call("inspect_analysis_view", {
      source: { kind: "retained-evidence", evidence_id: retained.evidence_id },
      view,
    });
    expect(mcpView.isError).not.toBe(true);
    const mcpEvidence = parseEvidence(mcpView.structuredContent);
    const expected = [
      { name: "category", record_ordinals: [0, 1] },
      { name: "page", record_ordinals: [1] },
      { name: "plus+name", record_ordinals: [0] },
      { name: "repeat", record_ordinals: [0, 1] },
      { name: "space name", record_ordinals: [0, 1] },
    ];
    for (const result of [evidence, mcpEvidence]) {
      expect(result.normalized_result).toMatchObject({
        groups: [
          {
            method: "GET",
            origin,
            path_template: "/items/{numeric}",
            query_parameter_names: expected,
          },
        ],
        records: { examined: 2, total: 2 },
      });
      expect(JSON.stringify(result)).not.toContain("QUERY_VALUE_ONLY");
      expect(result.evidence_links).toHaveLength(1);
    }
    const defaultView = await call("inspect_analysis_view", {
      source: { kind: "retained-evidence", evidence_id: retained.evidence_id },
      view: { kind: "api-surface" },
    });
    const ordinary = parseEvidence(defaultView.structuredContent);
    expect(JSON.stringify(ordinary.normalized_result)).not.toContain(
      "query_parameter_names",
    );
  },
);
