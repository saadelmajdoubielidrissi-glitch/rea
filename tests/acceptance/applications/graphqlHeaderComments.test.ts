import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { parseEvidence } from "../../../src/domain/evidence.js";
import { javascriptApplicationAnalysisResultSchema } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

cliTest.for(["CLI", "stdio MCP"] as const)(
  "retains named GraphQL header comments and source provenance through %s",
  async (surface, { cli }) => {
    const root = await createTestTempDirectory("rea-graphql-header-comments-");
    const documents = [
      "query # header\nGetUser { user }",
      "mutation UpdateUser # selection\r\n{ user }",
      "subscription OnUser { # first field\ruser }",
      "query # anonymous\n{ user }",
      "query Hidden # selection set is still commented: { user }",
      "query text parameters",
    ];
    const source = [
      `const documents = ${JSON.stringify(documents)};`,
      'throw new Error("This fixture must not execute");',
    ].join("\n");
    await writeFile(join(root, "main.js"), source);
    const digest = createHash("sha256").update(source).digest("hex");
    let document: unknown;
    if (surface === "CLI") {
      const response = await cli.run({
        arguments: ["analyze-javascript-application", root, "--json"],
      });
      expect(response.exitCode, response.stderr).toBe(0);
      document = response.json;
    } else {
      const { call } = await connectLocalToolsMcp();
      const response = await call("analyze_javascript_application", {
        input_path: root,
      });
      expect(response.isError, JSON.stringify(response)).not.toBe(true);
      document = response.structuredContent;
    }
    const { graph } = javascriptApplicationAnalysisResultSchema.parse(
      parseEvidence(document).normalized_result,
    );
    const operations = graph.nodes.flatMap(({ observations }) =>
      observations.filter(({ properties }) =>
        String(properties.mechanism).startsWith("graphql:"),
      ),
    );
    expect(
      operations
        .map(({ properties }) => ({
          value: properties.value,
          mechanism: properties.mechanism,
        }))
        .sort((left, right) =>
          String(left.value).localeCompare(String(right.value)),
        ),
    ).toEqual([
      { value: "GetUser", mechanism: "graphql:query" },
      { value: "OnUser", mechanism: "graphql:subscription" },
      { value: "UpdateUser", mechanism: "graphql:mutation" },
    ]);
    for (const { evidence } of operations) {
      expect(evidence.authority).toBe("ast-static-analysis");
      expect(evidence.artifact).toMatchObject({
        available: true,
        sha256: digest,
      });
      expect(evidence.location).toMatchObject({
        available: true,
        value: { kind: "source-range", source: "main.js" },
      });
    }
  },
);
