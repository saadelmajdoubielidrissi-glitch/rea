import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import { setTimeout as delay } from "node:timers/promises";

import { chromium } from "playwright-core";

import { PlaywrightScenarioSession } from "../../dist/browser/PlaywrightScenarioSession.js";
import { PlaywrightScenarioServiceWorkers } from "../../dist/browser/PlaywrightScenarioServiceWorkers.js";
import { createBrowserScenarioProvider } from "../../dist/composition/browserScenario.js";
import { browserScenarioSchema } from "../../dist/domain/browserScenario.js";
import { runScenarioCli } from "./browser-scenario-verifier.mjs";

const startSite = async () => {
  let otherOrigin;
  const server = createServer((request, response) => {
    const path = new URL(request.url, "http://localhost").pathname;
    if (path === "/sw.js") {
      response.setHeader("content-type", "application/javascript");
      response.end(`self.addEventListener("install", () => self.skipWaiting());
        self.addEventListener("activate", event => event.waitUntil(clients.claim()));
        self.addEventListener("fetch", event => {
          if (new URL(event.request.url).pathname === "/probe")
            event.respondWith(new Response("worker"));
        });`);
    } else if (path === "/probe") {
      response.end("network");
    } else if (path === "/failed-navigation") {
      response.destroy();
    } else {
      response.setHeader("content-type", "text/html");
      response.end(`<!doctype html><p id="state">ready</p>
        <a id="navigate" href="${otherOrigin}/">Navigate</a>
        ${path === "/frame" ? `<iframe src="${otherOrigin}/"></iframe>` : ""}
        ${
          path === "/register"
            ? `<script>
          navigator.serviceWorker.register('/sw.js').then(
            () => document.querySelector('#state').textContent = 'registered',
            () => {
              document.querySelector('#state').textContent = 'blocked';
              document.querySelector('#state').dataset.blocked = 'true';
            });
        </script>`
            : ""
        }`);
    }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return {
    origin: `http://127.0.0.1:${server.address().port}`,
    setOtherOrigin: (origin) => {
      otherOrigin = origin;
    },
    close: async () => {
      const closed = once(server, "close");
      server.close();
      server.closeAllConnections();
      await closed;
    },
  };
};

/** Real attached-page policy checks, with caller-owned workers on a second origin. */
export async function verifyScenarioServiceWorkers(endpoint, targetId) {
  const first = await startSite();
  const second = await startSite();
  first.setOtherOrigin(second.origin);
  second.setOtherOrigin(first.origin);
  const observer = await chromium.connectOverCDP(endpoint);
  let provider = createBrowserScenarioProvider(process.env);
  let session;
  let failure;
  try {
    let page;
    for (const context of observer.contexts()) {
      for (const candidate of context.pages()) {
        const cdp = await context.newCDPSession(candidate);
        const { targetInfo } = await cdp.send("Target.getTargetInfo");
        await cdp.detach();
        if (targetInfo.targetId === targetId) page = candidate;
      }
    }
    assert.ok(page, "External fixture page disappeared");
    const scenarioFor = (url, actions = [], policy = "block") =>
      browserScenarioSchema.parse({
        browser: {
          mode: "connect",
          cdp_endpoint: endpoint,
          target_id: targetId,
        },
        start_url: { url },
        environment: { service_workers: policy },
        actions:
          actions.length === 0
            ? [
                {
                  step_id: "settle",
                  action: "wait_for_timeout",
                  duration_ms: 1,
                },
              ]
            : actions,
        capture: { events: [], after_each_step: ["dom"], at_end: ["dom"] },
      });
    const assertRestored = async () => {
      assert.equal(page.isClosed(), false);
      assert.equal(
        await page.evaluate(() =>
          ServiceWorkerContainer.prototype.register
            .toString()
            .includes("[native code]"),
        ),
        true,
      );
    };
    const assertRejected = async (scenario) => {
      const result = await provider.captureScenario(scenario);
      assert.equal(
        result.ok,
        false,
        "Worker-influenced capture unexpectedly succeeded",
      );
      assert.equal(result.error.reason, "target_not_allowed");
      assert.equal(
        result.error.partialObservation.capture.browser.cleanup,
        "disconnected-external",
      );
      await assertRestored();
    };

    // A fresh attached origin blocks registration, then restores both the
    // current document and future documents when its transport disconnects.
    const clean = scenarioFor(`${first.origin}/register`, [
      {
        step_id: "registration-rejected",
        action: "wait_for",
        locator: { kind: "css", selector: "#state[data-blocked='true']" },
        state: "visible",
      },
    ]);
    const cleanCapture = (await runScenarioCli(clean)).normalized_result;
    assert.ok(cleanCapture.steps.every(({ status }) => status === "completed"));
    assert.equal(cleanCapture.browser.cleanup, "disconnected-external");
    await assertRestored();
    await page.reload();
    await page.getByText("registered", { exact: true }).waitFor();
    await page.evaluate(async () => {
      for (const registration of await navigator.serviceWorker.getRegistrations())
        await registration.unregister();
    });
    await page.goto("about:blank");

    // The caller installs a real worker at a different origin, then moves the
    // selected target away before REA attaches. Its registration must survive.
    await page.goto(second.origin);
    await page.evaluate(async () => {
      await navigator.serviceWorker.register("/sw.js");
      await navigator.serviceWorker.ready;
    });
    await page.reload();
    assert.equal(
      await page.evaluate(async () => (await fetch("/probe")).text()),
      "worker",
    );
    await page.goto("about:blank");
    await assertRejected(scenarioFor(second.origin));
    await page.goto("about:blank");
    await assertRejected(
      scenarioFor(first.origin, [
        {
          step_id: "cross-origin",
          action: "goto",
          destination: { url: second.origin },
          wait_until: "load",
        },
      ]),
    );
    await page.goto("about:blank");
    await assertRejected(
      scenarioFor(first.origin, [
        {
          step_id: "link-navigation",
          action: "click",
          locator: { kind: "css", selector: "#navigate" },
        },
        { step_id: "loaded", action: "wait_for_timeout", duration_ms: 100 },
      ]),
    );
    await page.goto("about:blank");
    await assertRejected(scenarioFor(`${first.origin}/frame`));

    const allowed = await provider.captureScenario(
      scenarioFor(second.origin, [], "allow"),
    );
    if (!allowed.ok) throw allowed.error;
    assert.ok(
      allowed.value.steps.every(({ status }) => status === "completed"),
    );
    assert.equal(
      await page.evaluate(async () => (await fetch("/probe")).text()),
      "worker",
    );
    assert.equal(
      await page.evaluate(
        async () => (await navigator.serviceWorker.getRegistrations()).length,
      ),
      1,
    );

    // Restoration also runs after navigation failure and active cancellation.
    await page.goto("about:blank");
    const failed = await provider.captureScenario(
      scenarioFor(`${first.origin}/failed-navigation`),
    );
    assert.equal(failed.ok, false);
    // Chromium completes its error-document transition after goto rejects.
    await page.waitForSelector("#main-frame-error", { state: "attached" });
    // A context replacement can defer restoration. Retained cleanup must
    // restore the replacement document before releasing the external page.
    await provider.close();
    provider = createBrowserScenarioProvider(process.env);
    await page.goto(first.origin);
    await assertRestored();
    const cancellation = new AbortController();
    const pending = provider.captureScenario(
      scenarioFor(`${first.origin}/register`, [
        {
          step_id: "wait",
          action: "wait_for",
          locator: { kind: "css", selector: "#absent" },
          state: "visible",
          timeout_ms: 30_000,
        },
      ]),
      { signal: cancellation.signal },
    );
    try {
      const deadline = Date.now() + 10_000;
      while ((await page.locator("#state").textContent()) !== "blocked") {
        assert.ok(
          Date.now() < deadline,
          "Scenario never applied registration policy",
        );
        await delay(25);
      }
    } finally {
      cancellation.abort();
    }
    const cancelled = await pending;
    assert.ok(
      !cancelled.ok ||
        cancelled.value.steps.some(({ status }) => status === "cancelled"),
    );
    await assertRestored();

    // Caller changes made after installation belong to the caller, too.
    session = await PlaywrightScenarioSession.open(
      scenarioFor(first.origin),
      process.env,
      {},
    );
    await page.evaluate(() => {
      ServiceWorkerContainer.prototype.register =
        function callerReplacement() {};
    });
    await session.close();
    session = undefined;
    assert.equal(
      await page.evaluate(() => ServiceWorkerContainer.prototype.register.name),
      "callerReplacement",
    );
    await page.reload();
    await assertRestored();
    await page.evaluate(() => {
      delete ServiceWorkerContainer.prototype.register;
    });
    const policyBrowser = await chromium.connectOverCDP(endpoint);
    try {
      let policyPage;
      for (const context of policyBrowser.contexts()) {
        for (const candidate of context.pages()) {
          const cdp = await context.newCDPSession(candidate);
          const { targetInfo } = await cdp.send("Target.getTargetInfo");
          await cdp.detach();
          if (targetInfo.targetId === targetId) policyPage = candidate;
        }
      }
      assert.ok(policyPage);
      const policy = new PlaywrightScenarioServiceWorkers(policyPage);
      await policy.initialize();
      await policy.close();
    } finally {
      await policyBrowser.close();
    }
    assert.equal(
      await page.evaluate(() =>
        Object.hasOwn(ServiceWorkerContainer.prototype, "register"),
      ),
      false,
    );
    await page.reload();
    await assertRestored();
    return {
      mocked: false,
      cli: true,
      production_provider: true,
      initial_navigation: true,
      action_navigation: true,
      cross_origin_frame: true,
      allow_preserves_existing_worker: true,
      registration_blocked: true,
      live_document_and_reload_restored: true,
      failure_and_cancellation_cleanup: true,
      caller_replacement_preserved: true,
      caller_original_absence_preserved: true,
      external_target_preserved: true,
    };
  } catch (cause) {
    failure = cause;
    throw cause;
  } finally {
    await session?.close();
    try {
      await provider.close();
    } catch (cleanupFailure) {
      if (failure !== undefined)
        throw new AggregateError([failure, cleanupFailure]);
      throw cleanupFailure;
    } finally {
      await observer.close();
      await first.close();
      await second.close();
    }
  }
}
