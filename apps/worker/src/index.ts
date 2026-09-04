/**
 * Cloudflare Worker entry point.
 *
 * This module does only environment wiring and Worker export. All routing,
 * authorization, and data access live in app.ts / db.ts / google.ts / tokens.ts.
 */
import { validateEnv, type Env } from "./env.js";
import { handleRequest, handleScheduled } from "./app.js";

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    let config;
    try {
      config = validateEnv(env);
    } catch (e) {
      return new Response(JSON.stringify({ error: "Server misconfigured" }), {
        status: 500,
        headers: { "content-type": "application/json" },
      });
    }
    try {
      return await handleRequest(req, config);
    } catch (e) {
      const message = e instanceof Error ? e.message : "Request failed";
      // Safe route-specific error page. Import lazily to keep the hot path lean.
      const { errorPage } = await import("./pages.js");
      return new Response(errorPage(message), {
        status: 400,
        headers: { "content-type": "text/html;charset=utf-8" },
      });
    }
  },

  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    let config;
    try {
      config = validateEnv(env);
    } catch {
      // Misconfigured environment: nothing to clean up.
      return;
    }
    await handleScheduled(config);
  },
};
