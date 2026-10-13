import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { z } from "zod";

import { evaluateAgentTranscript } from "../dist/evaluation/AgentEval.js";
import { parseAgentTranscript } from "../dist/evaluation/AgentTranscript.js";
import {
  createAgentEvaluationFixtures,
  agentFixtureClaims,
  agentFixtureAnswerInstructions,
} from "../dist/evaluation/AgentEvaluationFixtures.js";
import {
  agentEvaluationPassed,
  summarizeFactualCorrectness,
} from "../dist/evaluation/AgentEvaluationReport.js";
import { PRODUCT_IDENTITY } from "../dist/identity.js";
import {
  cleanupOwnedProcessGroup,
  verifyNoTokenOwnedProcesses,
} from "../dist/process/ProcessOwnership.js";
import { systemProcessOwnershipHost } from "../dist/process/ProcessOwnershipObservation.js";
import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
} from "../dist/process/ProviderProcess.js";
import {
  agentEvalEnvironment,
  prepareAgentEvalClient,
  selectAgentEvalClient,
} from "./lib/agent-eval-clients.mjs";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const verifierRun = createVerifierRun();
const timeoutMs = Number(process.env.REA_AGENT_EVAL_TIMEOUT_MS ?? 480_000);
const client = selectAgentEvalClient(
  process.env.REA_AGENT_EVAL_CLIENT,
  repositoryRoot,
);
const optionalModel = process.env.REA_AGENT_EVAL_MODEL;

if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 10_000)
  throw new Error("REA_AGENT_EVAL_TIMEOUT_MS must be an integer >= 10000");
// Codex refuses helper aliases when CODEX_HOME is under the OS temp directory.
// Keep the disposable account in a private cache, then remove the owned run.
const evaluationParent = resolve(
  process.env.REA_AGENT_EVAL_ROOT ??
    join(homedir(), ".cache", "rea-agent-evaluations"),
);
await mkdir(evaluationParent, { recursive: true, mode: 0o700 });
const evaluationRoot = await mkdtemp(join(evaluationParent, "run-"));
const fixtureRoot = join(evaluationRoot, "targets");
const account = join(evaluationRoot, "account");
// Copied credentials are registered here before they are written.
const authPaths = [];
// The run scope retains process authority until both stopping and token verification finish.
const scenarioProcesses = new Map();
const ownershipReceipt = join(evaluationRoot, "process-ownership.json");

try {
  const clientVersion = await readCommandVersion(
    client.command,
    agentEvalEnvironment({
      account,
      runId: verifierRun.run_id,
      client: {
        environment:
          client.id === "gemini-cli" ? { GEMINI_CLI_NO_RELAUNCH: "1" } : {},
      },
    }),
  );
  await Promise.all([mkdir(fixtureRoot, { recursive: true }), mkdir(account)]);
  // Reuse authentication only. User config, plugins, rules, history and skills
  // must not make a fresh installed-skill trial pass accidentally.
  const prepared = await prepareAgentEvalClient(client, {
    evaluationRoot,
    account,
    model: optionalModel,
    authPaths,
  });
  const evaluationEnvironment = agentEvalEnvironment({
    account,
    runId: verifierRun.run_id,
    client: prepared,
  });
  for (const approval of ["--dry-run", "--yes"]) {
    await runProcess(
      process.execPath,
      [
        join(repositoryRoot, "scripts/rea.mjs"),
        "setup",
        "--client",
        client.setupClient,
        approval,
        "--json",
      ],
      evaluationRoot,
      120_000,
      evaluationEnvironment,
    );
  }
  const installedSkill = await readFile(
    join(prepared.skillDirectory, "SKILL.md"),
    "utf8",
  );
  if (!installedSkill.includes(`  version: "${PRODUCT_IDENTITY.skillVersion}"`))
    throw new Error("Setup did not install the current packaged REA skill");
  const requestedScenarioIds = new Set(
    (process.env.REA_AGENT_EVAL_SCENARIOS ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter((value) => value.length > 0),
  );
  const targets = await createTargets(
    fixtureRoot,
    requestedScenarioIds.size === 0 || requestedScenarioIds.has("managed"),
  );
  const allScenarios = [
    {
      id: "native",
      expectedFirstTool: "open_binary",
      requiresEvidence: false,
      requiredAnswerTermGroups: [["unavailable", "could not", "provider"]],
      // The verifier authorizes these named session operations, not arbitrary
      // writes or runtime execution. Missing-engine behavior stays observable.
      approvedTools: ["open_binary", "close_binary"],
      requiredToolSubsequence: ["open_binary", "close_binary"],
      prompt: `Explain what static artifact evidence establishes about the shipped native program at ${targets.native}. Do not execute the target or install tools. Clearly state unavailable provider evidence, and close any analysis session you opened before finishing.`,
    },
    {
      id: "asar",
      expectedFirstTool: "analyze_javascript_application",
      requiresEvidence: true,
      requiredAnswerTermGroups: [
        ["profileapi"],
        ["profile:read"],
        ["preload", "contextbridge"],
      ],
      prompt: `Explain how the desktop application at ${targets.javascript} exposes APIs to its renderer. Base the answer on the shipped application artifact, and state what remains unknown.`,
    },
    {
      id: "asar-zh",
      fixtureScenarioId: "asar",
      expectedFirstTool: "analyze_javascript_application",
      requiresEvidence: true,
      requiredAnswerTermGroups: [["profileapi"], ["profile:read"]],
      prompt: `請靜態分析已交付的 Electron 程式 ${targets.javascript}，說明 renderer 如何透過 preload 讀取 profile，以及 main handler 的關係。不要執行目標或安裝分析引擎；引用完整的產出 Evidence，保留 runtime 未知事項。`,
    },
    {
      id: "javascript-module-view",
      expectedFirstTool: "analyze_javascript_application",
      requiresEvidence: true,
      requiredToolSubsequence: [
        "analyze_javascript_application",
        "inspect_analysis_view",
        "inspect_analysis_view",
      ],
      requiredAnswerTermGroups: [
        ["main.js"],
        ["node", "identity"],
        ["observations", "recorded"],
      ],
      prompt: `Inspect the recorded module identity, exports and observations for main.js in the shipped JavaScript tree ${targets.largeJavascript}. Use REA without directly reading target files or executing the target. Keep results focused on that module, cite Evidence, and state the limits of what its module view establishes.`,
    },
    {
      id: "missing-target",
      expectedFirstTool: null,
      requiresEvidence: false,
      requiredAnswerTermGroups: [],
      prompt:
        'Reverse engineer my desktop app and explain how it saves user settings. Use static analysis; do not install software. End with one JSON object containing status ("needs_target" or "analyzed"), requested_input ("app_name_or_artifact_path" or null), and question (a string or null).',
    },
    {
      id: "javascript-export-shape",
      expectedFirstTool: "analyze_javascript_application",
      requiresEvidence: true,
      requiredToolSubsequence: [
        "analyze_javascript_application",
        "analyze_javascript_application",
        "compare_javascript_export_shapes",
      ],
      requiredAnswerTermGroups: [
        ["/depth", "depth"],
        [
          "literal value `1`",
          "literal `1`",
          "depth: 1",
          '"depth": 1',
          "depth = 1",
        ],
        ["static", "inferred"],
        ["runtime", "behavioral probes"],
      ],
      prompt: `Without directly reading target files, compare the default export in parser.mjs between ${targets.javascriptShapeLeft} and ${targets.javascriptShapeRight}. Use REA to analyze each shipped artifact and then compare its exact static export return shapes. State the exact heading-shape change, cite produced Evidence, and distinguish static inference from runtime semantics.`,
    },
    {
      id: "managed",
      expectedFirstTool: "inspect_managed_artifact",
      requiresEvidence: true,
      requiredAnswerTermGroups: [["profile"], ["main", "entry point"]],
      requiredToolSubsequence: [
        "inspect_managed_artifact",
        "inspect_managed_members",
      ],
      prompt: `Explain the public managed types and entry point in ${targets.managed}. Use shipped-artifact evidence and distinguish unavailable behavior from observed metadata.`,
    },
    {
      id: "browser",
      approvedTools: ["list_browser_targets"],
      expectedFirstTool: "list_browser_targets",
      requiresEvidence: false,
      requiredAnswerTermGroups: [
        ["unavailable", "could not", "connection", "endpoint"],
      ],
      prompt:
        "A user-owned page is already open at http://127.0.0.1:3000 through the approved local debugging endpoint http://127.0.0.1:9222. Inspect what is available without navigating or executing page code, and report any authority or availability limits.",
    },
    {
      id: "navigation-context",
      expectedFirstTool: "get_navigation_context",
      requiresEvidence: false,
      requiredAnswerTermGroups: [["unavailable", "could not", "session"]],
      prompt:
        "Report the selected document, current address, and containing procedure from the current native-analysis session in one coherent request. If no native session is available, report that limitation plainly.",
    },
    {
      id: "address-context",
      expectedFirstTool: "inspect_address_context",
      requiresEvidence: false,
      requiredAnswerTermGroups: [["unavailable", "could not", "session"]],
      prompt:
        "Inspect explicit address 0x401000 in the current native-analysis session. Report its analyzed name, containing procedure, regular comment, inline comment, and matching bookmarks. If no native session is available, report that limitation plainly.",
    },
  ];
  const scenarios =
    requestedScenarioIds.size === 0
      ? allScenarios
      : allScenarios.filter(({ id }) => requestedScenarioIds.has(id));
  if (
    requestedScenarioIds.size > 0 &&
    scenarios.length !== requestedScenarioIds.size
  )
    throw new Error(
      `Unknown or duplicate REA_AGENT_EVAL_SCENARIOS value: ${[...requestedScenarioIds].join(",")}`,
    );
  const results = [];
  for (const scenario of scenarios) {
    process.stderr.write(
      `Running ${client.id} agent evaluation: ${scenario.id}\n`,
    );
    const fixtureId = scenario.fixtureScenarioId ?? scenario.id;
    const fixtureClaims = agentFixtureClaims(fixtureId, targets);
    const answerInstructions = agentFixtureAnswerInstructions(fixtureId);
    const execution = await runClient(
      evaluationEnvironment,
      await prepared.arguments(
        answerInstructions.length === 0
          ? scenario.prompt
          : `${scenario.prompt}\n\nThis closed factual rubric needs complete producer Evidence in the transcript. Request complete detail on each initial inspection or analysis when supported; summary or view records alone are not accepted by this rubric.\n\n${answerInstructions}`,
        scenario.approvedTools ?? [],
      ),
      scenario.id,
    );
    const transcriptDirectory = process.env.REA_AGENT_EVAL_TRANSCRIPT_DIR;
    if (transcriptDirectory !== undefined) {
      const transcriptPath = resolve(
        transcriptDirectory,
        `${scenario.id}.jsonl`,
      );
      await mkdir(dirname(transcriptPath), { recursive: true });
      await writeFile(
        transcriptPath,
        `${execution.events.map((event) => JSON.stringify(event)).join("\n")}\n`,
      );
    }
    const metrics = evaluateAgentTranscript(
      parseAgentTranscript(client.id, execution.events),
      scenario.expectedFirstTool,
      {
        requireEvidence: scenario.requiresEvidence,
        requiredAnswerTermGroups: scenario.requiredAnswerTermGroups,
        requiredToolSubsequence: scenario.requiredToolSubsequence,
        forbidInputValidationFailures: true,
        ...(fixtureClaims === undefined ? {} : { fixtureClaims }),
      },
    );
    // Fixtures are deliberately visible beside prior investigation artifacts.
    // Their existence does not identify the unnamed app in this request.
    const targetClarificationPassed =
      scenario.expectedFirstTool === null
        ? validTargetClarification(metrics.finalMessage)
        : undefined;
    const result = {
      id: scenario.id,
      expectedFirstTool: scenario.expectedFirstTool,
      requiresEvidence: scenario.requiresEvidence,
      requiredAnswerTermGroups: scenario.requiredAnswerTermGroups,
      requiredToolSubsequence: scenario.requiredToolSubsequence ?? [],
      configuredClaimIds: fixtureClaims?.map(({ id }) => id) ?? [],
      exitCode: execution.exitCode,
      stderr: execution.stderr,
      ...metrics,
      ...(targetClarificationPassed === undefined
        ? {}
        : { targetClarificationPassed }),
    };
    results.push(result);
    process.stderr.write(
      `${scenario.id}: first=${metrics.firstTool ?? "none"}, calls=${String(metrics.reaCalls.length)}, repeats=${String(metrics.repeatedCallCount)}, validation_failures=${String(metrics.inputValidationFailureCount)}, input_tokens=${String(metrics.inputTokens)}\n`,
    );
  }

  const factualCorrectness = summarizeFactualCorrectness(results);
  const summary = {
    schemaVersion: 5,
    evaluationScope: "routing_workflow_and_configured_fixture_claims",
    factualCorrectness,
    verifier_run: await completeVerifierRun(verifierRun),
    client: client.id,
    clientCommand: client.command,
    clientVersion,
    ...(client.id === "codex"
      ? { codex: client.command, codexVersion: clientVersion }
      : {}),
    model: optionalModel ?? null,
    installation: {
      method: `rea_setup_${client.setupClient}`,
      isolatedHome: true,
      isolatedClientHome: true,
      ...(client.id === "codex" ? { isolatedCodexHome: true } : {}),
      skillVersion: PRODUCT_IDENTITY.skillVersion,
      authentication: "caller_auth_only_removed_after_run",
    },
    scenarios: results,
    totals: {
      scenarios: results.length,
      naturalUse: results.filter(({ naturalUse }) => naturalUse).length,
      correctFirstTool: results.filter(
        ({ correctFirstTool }) => correctFirstTool,
      ).length,
      repeatedCallCount: results.reduce(
        (total, { repeatedCallCount }) => total + repeatedCallCount,
        0,
      ),
      inputValidationFailureCount: results.reduce(
        (total, { inputValidationFailureCount }) =>
          total + inputValidationFailureCount,
        0,
      ),
      requiredToolSubsequence: results.filter(
        ({ requiredToolSubsequenceMet }) => requiredToolSubsequenceMet,
      ).length,
      inputTokens: results.reduce(
        (total, { inputTokens }) => total + inputTokens,
        0,
      ),
      cachedInputTokens: results.reduce(
        (total, { cachedInputTokens }) => total + cachedInputTokens,
        0,
      ),
      answerHeuristicsMet: results.filter(({ answerHeuristicsMet }) =>
        Boolean(answerHeuristicsMet),
      ).length,
      epistemicCuePresent: results.filter(({ epistemicCuePresent }) =>
        Boolean(epistemicCuePresent),
      ).length,
      factualScenariosPassed: factualCorrectness.counts.passed,
      factualScenariosFailed: factualCorrectness.counts.failed,
      factualScenariosNotAssessed: factualCorrectness.counts.notAssessed,
    },
  };
  const encoded = `${JSON.stringify(summary, null, 2)}\n`;
  process.stdout.write(encoded);
  const reportPath = process.env.REA_AGENT_EVAL_REPORT_PATH;
  if (reportPath !== undefined) {
    await mkdir(dirname(resolve(reportPath)), { recursive: true });
    await writeFile(resolve(reportPath), encoded);
  }

  const failed = results.filter((result) => !agentEvaluationPassed(result));
  if (failed.length > 0)
    throw new Error(
      `Agent routing/workflow/answer checks failed: ${failed.map(({ id }) => id).join(", ")}`,
    );
} finally {
  // Retry retained ownership before releasing credentials or the run root.
  for (const owned of scenarioProcesses.values()) await stopScenario(owned);
  if (scenarioProcesses.size > 0) {
    await writeFile(
      ownershipReceipt,
      `${JSON.stringify(
        {
          schema_version: 1,
          evaluation_root: evaluationRoot,
          authentication_paths: authPaths,
          processes: [...scenarioProcesses.values()].map(
            ({ ownership, scenarioId, lastCleanup }) => ({
              ownership,
              scenario_id: scenarioId,
              cleanup: lastCleanup,
            }),
          ),
        },
        null,
        2,
      )}\n`,
      { mode: 0o600, flag: "wx" },
    );
    console.error(
      `Agent evaluation cleanup is unresolved; retained private resources and ownership receipt: ${ownershipReceipt}`,
    );
    process.exitCode = 1;
  } else {
    // Fixture retention never retains auth after verified process cleanup.
    await Promise.all(authPaths.map((path) => rm(path, { force: true })));
    if (process.env.REA_AGENT_EVAL_KEEP_FIXTURES !== "true")
      await rm(evaluationRoot, { recursive: true, force: true });
  }
}

async function createTargets(root, includeManaged) {
  const fixtures = await createAgentEvaluationFixtures(root, repositoryRoot);
  const largeJavascript = join(root, "large-app");
  await mkdir(join(largeJavascript, "lib"), { recursive: true });
  await Promise.all([
    writeFile(
      join(largeJavascript, "package.json"),
      '{"name":"large-app","main":"main.js"}\n',
    ),
    writeFile(
      join(largeJavascript, "main.js"),
      'const { ipcMain } = require("electron");\nipcMain.handle("profile:read", (_event, id) => ({ id }));\n',
    ),
    ...Array.from({ length: 180 }, (_, index) =>
      writeFile(
        join(largeJavascript, "lib", `formatter-${String(index)}.js`),
        `export const format = (value) => String(value).trim();\n`,
      ),
    ),
  ]);

  const managedOutput = join(root, "managed-output");
  if (includeManaged) {
    const managedProject = join(root, "managed-project");
    await mkdir(managedProject, { recursive: true });
    await Promise.all([
      writeFile(
        join(managedProject, "AgentEval.csproj"),
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable></PropertyGroup></Project>\n',
      ),
      writeFile(
        join(managedProject, "Program.cs"),
        'namespace AgentEval; public sealed record Profile(string Id); public static class Program { public static void Main() => Console.WriteLine(new Profile("fixture")); }\n',
      ),
    ]);
    await runProcess(
      "dotnet",
      [
        "build",
        join(managedProject, "AgentEval.csproj"),
        "--configuration",
        "Release",
        "--output",
        managedOutput,
        "--nologo",
      ],
      root,
      120_000,
    );
  }
  return {
    native: "/bin/true",
    ...fixtures,
    largeJavascript,
    managed: join(managedOutput, "AgentEval.dll"),
    ...(includeManaged
      ? {
          managedSha256: createHash("sha256")
            .update(await readFile(join(managedOutput, "AgentEval.dll")))
            .digest("hex"),
        }
      : {}),
  };
}

function validTargetClarification(message) {
  const schema = z.strictObject({
    status: z.literal("needs_target"),
    requested_input: z.literal("app_name_or_artifact_path"),
    question: z.string().refine((value) => value.trim().length > 0),
  });
  try {
    return schema.safeParse(JSON.parse(message)).success;
  } catch (cause) {
    if (cause instanceof SyntaxError) return false;
    throw cause;
  }
}

/**
 * Run one client scenario as an owned process tree. The client and the REA MCP
 * server it starts inherit a scenario run token; timeout or completion ends
 * with token-verified cleanup of every owned process before the run continues.
 */
async function runClient(env, arguments_, scenarioId) {
  const events = [];
  const nonJson = [];
  const { snapshot } = await runOwnedCommand({
    command: client.command,
    arguments: arguments_,
    runId: `${verifierRun.run_id}-${client.id}-${scenarioId}`,
    cwd: evaluationRoot,
    env,
    timeoutMs,
    captureStdout: false,
    onStarted: (launch) => {
      const lines = createInterface({ input: launch.process.stdout });
      lines.on("line", (line) => {
        try {
          events.push(JSON.parse(line));
        } catch {
          if (nonJson.join("").length < 32_768)
            nonJson.push(`non-json stdout: ${line}\n`);
        }
      });
      return () => lines.close();
    },
  });
  return {
    events,
    exitCode: snapshot.exitCode ?? 1,
    stderr: `${nonJson.join("")}${snapshot.stderr.text}`.slice(0, 32_768),
  };
}

/** Run a command and its descendants under the evaluation's retained owner. */
async function runOwnedCommand({
  command,
  arguments: arguments_,
  runId,
  cwd,
  env,
  timeoutMs: processTimeoutMs,
  captureStdout,
  onStarted,
}) {
  // Processes alive before launch cannot belong to this scenario. The baseline
  // lets a token sweep find reparented MCP servers without failing on
  // unrelated processes whose environment is unreadable.
  const captureBaseline = await systemProcessOwnershipHost.captureBaseline?.();
  const launch = await spawnOwnedProviderProcess({
    command,
    arguments: arguments_,
    runId,
    expectedCommand: null,
    cwd,
    env,
    // The allowlisted environment is complete; nothing else is inherited.
    hostEnvironment: {},
  });
  const ownership = {
    ...launch.ownership,
    sweepTokenOwnedProcesses: true,
    ...(captureBaseline === undefined ? {} : { captureBaseline }),
  };
  const owned = {
    ownership,
    scenarioId: runId,
    supervisor: undefined,
    stop: () => launch.cleanup?.() ?? cleanupOwnedProcessGroup(ownership),
    lastCleanup: undefined,
  };
  // Register before stream and supervisor setup so outer cleanup always owns it.
  scenarioProcesses.set(ownership.runId, owned);
  const supervisor = new ProviderProcessSupervisor(
    {
      ...launch,
      ownsProcessLifetime: true,
      cleanup: owned.stop,
    },
    {
      captureStdout,
      maxDiagnosticBytes: captureStdout ? 8_192 : 32_768,
    },
  );
  owned.supervisor = supervisor;
  let disposeOutput;
  let exited = false;
  let stopped;
  try {
    disposeOutput = onStarted?.(launch);
    exited = await supervisor.waitForExit(processTimeoutMs);
    if (exited) await supervisor.waitForOutputClose(5_000);
  } finally {
    // Owned descendants are stopped even when waiting or output setup failed.
    stopped = await stopScenario(owned);
    disposeOutput?.();
  }
  if (!stopped.cleaned)
    throw new Error(
      `${command} process cleanup incomplete; ownership and resources retained at ${evaluationRoot}: ${JSON.stringify(stopped)}`,
    );
  if (!exited)
    throw new Error(`${command} timed out after ${String(processTimeoutMs)}ms`);
  return { snapshot: supervisor.snapshot() };
}

/** Stop the launcher, then observe owned descendants rather than equating signal delivery with exit. */
async function stopScenario(owned) {
  try {
    // A previously verified signal request may still have left descendants alive.
    // Retry through the ownership primitive, which revalidates every live candidate.
    if (owned.lastCleanup !== undefined) await owned.stop();
    const stopped =
      owned.supervisor === undefined
        ? await owned.stop()
        : await owned.supervisor.stop();
    const deadline = performance.now() + 5_000;
    let verification;
    do {
      verification = await verifyNoTokenOwnedProcesses(
        owned.ownership.runId,
        systemProcessOwnershipHost,
        owned.ownership.captureBaseline,
        owned.ownership,
      );
      if (verification.cleaned) break;
      await delay(100);
    } while (performance.now() < deadline);
    const stoppedCleanly =
      owned.supervisor === undefined
        ? stopped.cleaned
        : stopped.status === "verified-cleanup" ||
          stopped.status === "already-exited";
    const result = {
      cleaned: stoppedCleanly && verification.cleaned,
      stopped,
      verification,
    };
    owned.lastCleanup = result;
    if (result.cleaned) {
      scenarioProcesses.delete(owned.ownership.runId);
      owned.supervisor?.dispose();
    }
    return result;
  } catch (cause) {
    const result = {
      cleaned: false,
      reason: cause instanceof Error ? cause.message : String(cause),
    };
    owned.lastCleanup = result;
    return result;
  }
}

async function runProcess(
  command,
  arguments_,
  cwd,
  timeout,
  env = process.env,
) {
  const child = spawn(command, arguments_, {
    cwd,
    env,
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    if (stderr.length < 32_768) stderr += chunk.toString("utf8");
  });
  const code = await new Promise((resolveExit, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`${command} timed out`));
    }, timeout);
    child.once("error", (cause) => {
      clearTimeout(timer);
      reject(cause);
    });
    child.once("exit", (value) => {
      clearTimeout(timer);
      resolveExit(value ?? 1);
    });
  });
  if (code !== 0)
    throw new Error(`${command} failed with ${String(code)}: ${stderr}`);
}

async function readCommandVersion(command, environment) {
  const { snapshot } = await runOwnedCommand({
    command,
    arguments: ["--version"],
    runId: `${verifierRun.run_id}-${client.id}-version`,
    cwd: repositoryRoot,
    env: environment,
    timeoutMs: 10_000,
    captureStdout: true,
  });
  if (snapshot.exitCode !== 0)
    throw new Error(
      `${command} --version failed with ${String(snapshot.exitCode)}: ${snapshot.stderr.text}`,
    );
  if (snapshot.diagnosticTruncated === true)
    throw new Error(
      `${command} --version output exceeded its retention budget`,
    );
  const version = snapshot.stdout.text.trim();
  if (version.length === 0)
    throw new Error(`${command} --version returned empty output`);
  return version;
}
