import { randomUUID } from "node:crypto";

import type { Page } from "playwright-core";

import { BrowserObservationError } from "../domain/browserObservationError.js";
import { withPlaywrightExecutionBoundary } from "./PlaywrightExecutionBoundary.js";

/** Owns only the registration wrapper; existing workers always belong to the caller. */
export class PlaywrightScenarioServiceWorkers {
  private readonly key = JSON.stringify(`rea-service-workers-${randomUUID()}`);
  #initialization: Promise<void> | undefined;
  #restoration: Promise<void> | undefined;

  constructor(private readonly page: Page) {}

  initialize(): Promise<void> {
    return (this.#initialization ??= this.install());
  }

  private async install(): Promise<void> {
    await this.assertBlocked();
    const script = `(() => {
      if (!("serviceWorker" in navigator)) return;
      const prototype = ServiceWorkerContainer.prototype;
      const descriptor = Object.getOwnPropertyDescriptor(prototype, "register");
      if (typeof descriptor?.value === "function" && Object.hasOwn(descriptor.value, Symbol.for(${this.key}))) return;
      const register = () => Promise.reject(new Error("service workers are blocked by scenario policy"));
      Object.defineProperty(register, Symbol.for(${this.key}), { value: descriptor });
      Object.defineProperty(prototype, "register", { ...descriptor, configurable: true, value: register });
    })()`;
    await this.page.addInitScript(script);
    for (const frame of this.page.frames()) {
      try {
        await frame.evaluate(script);
      } catch (cause: unknown) {
        if (!frame.isDetached()) throw cause;
      }
    }
  }

  async assertBlocked(): Promise<void> {
    // Check every current document, including origins reached through redirects,
    // actions and child frames. Inspecting only the pre-navigation page misses
    // registrations belonging to the actual scenario destination.
    for (const frame of this.page.frames()) {
      let hasWorker: unknown;
      try {
        hasWorker = await frame.evaluate(`(async () => {
        if (!("serviceWorker" in navigator)) return false;
        const serviceWorker = navigator.serviceWorker;
        if (serviceWorker.controller !== null) return true;
        return (await serviceWorker.getRegistrations()).length > 0;
        })()`);
      } catch (cause: unknown) {
        if (frame.isDetached()) continue;
        throw cause;
      }
      if (hasWorker)
        throw new BrowserObservationError(
          "capture_browser_scenario",
          "target_not_allowed",
        );
    }
  }

  close(): Promise<void> {
    const restoration = (this.#restoration ??= this.restore());
    void restoration.then(
      () => {
        if (this.#restoration === restoration) this.#restoration = undefined;
      },
      () => {
        if (this.#restoration === restoration) this.#restoration = undefined;
      },
    );
    return withPlaywrightExecutionBoundary(() => restoration, 1_000);
  }

  private async restore(): Promise<void> {
    // Cancellation races the operation; it does not cancel a sent Playwright
    // request. Let installation settle before undoing any late mutation.
    await this.#initialization?.catch(() => undefined);
    if (this.page.isClosed()) return;
    for (const frame of this.page.frames()) {
      if (frame.isDetached()) continue;
      try {
        // A failed/cancelled goto can still be switching execution contexts.
        // Restore the loaded replacement document rather than racing the old
        // realm; the cleanup boundary retains ownership if navigation stalls.
        await frame.waitForLoadState("load", { timeout: 0 });
        await frame.evaluate(`(() => {
        if (!("serviceWorker" in navigator)) return;
        const prototype = ServiceWorkerContainer.prototype;
        const register = Object.getOwnPropertyDescriptor(prototype, "register")?.value;
        if (typeof register !== "function" || !Object.hasOwn(register, Symbol.for(${this.key}))) return;
        const descriptor = register[Symbol.for(${this.key})];
        if (descriptor === undefined) delete prototype.register;
        else Object.defineProperty(prototype, "register", descriptor);
        })()`);
      } catch (cause: unknown) {
        if (!frame.isDetached()) throw cause;
      }
    }
    // Playwright removes its page init scripts when this scenario's transport
    // disconnects. Restore the live documents first, while retry is possible.
  }
}
