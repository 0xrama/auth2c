/**
 * D1 migration coverage: fresh application of all migrations succeeds, and the
 * 0001+0002 -> 0003 upgrade path correctly rejects a pre-hardening (NULL-nonce)
 * flow at callback time.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  applyAllMigrations,
  applyMigrationsMatching,
  call,
  db,
  googleCallback,
  makeGoogleDeps,
  resetTime,
  signGoogleIdToken,
} from "./_helper.js";

afterAll(() => {
  resetTime();
});

describe("migrations: fresh application", () => {
  beforeAll(async () => {
    await applyAllMigrations();
  });

  it("applies all migrations to a fresh DB and produces the full hardened schema", async () => {
    // Verify the post-hardening columns and tables are present.
    const flowCols = await db().prepare("PRAGMA table_info(flows)").all<{ name: string }>();
    const flowNames = flowCols.results.map((c) => c.name);
    expect(flowNames).toEqual(
      expect.arrayContaining([
        "id",
        "redirect_uri",
        "origin",
        "challenge",
        "client_state",
        "request_profile",
        "created_at",
        "nonce",
        "callback_claim_id",
        "callback_claimed_at",
      ]),
    );
    const codeCols = await db().prepare("PRAGMA table_info(codes)").all<{ name: string }>();
    expect(codeCols.results.map((c) => c.name)).toEqual(
      expect.arrayContaining(["code_hash", "created_at", "expires_at"]),
    );
    // Tables exist.
    for (const t of ["flows", "codes", "grants", "sessions"]) {
      const row = await db()
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?")
        .bind(t)
        .first<{ name: string }>();
      expect(row?.name).toBe(t);
    }
  });
});

describe("migrations: 0001+0002 -> 0003 upgrade path", () => {
  // NOTE: this describe block runs in its own beforeAll that applies only
  // 0001+0002, then seeds a pre-hardening flow, then applies 0003.
  let preHardeningFlowId: string;

  beforeAll(async () => {
    // Migrations are tracked in d1_migrations; if a prior file/test already
    // applied all migrations they will simply be skipped. The schema ends up in
    // the post-0003 state either way, so the seeded pre-hardening flow's
    // omitted nonce column defaults to NULL — exactly the post-upgrade state.
    await applyMigrationsMatching("0001", "0002");
    // Seed a pre-hardening flow (no nonce column reference).
    preHardeningFlowId = "pre-hardening-flow-0001";
    await db()
      .prepare(
        "INSERT INTO flows (id, redirect_uri, origin, challenge, client_state, request_profile, created_at) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .bind(
        preHardeningFlowId,
        "https://upgrade.test/cb",
        "https://upgrade.test",
        "x".repeat(43),
        "client-state-upgrade",
        0,
        // Recent timestamp so the flow is not considered expired by claimFlowForCallback.
        Date.UTC(2025, 11, 31, 23, 59, 0),
      )
      .run();
    // Now apply 0003 (adds nonce + claim columns; existing rows get NULL).
    await applyMigrationsMatching("0003");
  });

  it("rejects an old null-nonce flow at callback time and deletes it", async () => {
    // The flow row exists with a NULL nonce.
    const before = await db()
      .prepare("SELECT nonce FROM flows WHERE id = ?")
      .bind(preHardeningFlowId)
      .first<{ nonce: string | null }>();
    expect(before?.nonce).toBeNull();

    const idToken = await signGoogleIdToken({ sub: "google-upgrade", nonce: "anything" });
    const res = await googleCallback({
      flowId: preHardeningFlowId,
      google: makeGoogleDeps({ idToken }),
    });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("expired");

    // The flow was terminally deleted by the callback handler.
    const after = await db().prepare("SELECT 1 FROM flows WHERE id = ?").bind(preHardeningFlowId).first();
    expect(after).toBeNull();
    // And no grant/code was created.
    const grant = await db().prepare("SELECT 1 FROM grants WHERE origin = ?").bind("https://upgrade.test").first();
    const code = await db().prepare("SELECT 1 FROM codes WHERE origin = ?").bind("https://upgrade.test").first();
    expect(grant).toBeNull();
    expect(code).toBeNull();
  });

  it("call smoke-tests a JSON route against the upgraded schema", async () => {
    const res = await call("GET", "/.well-known/openid-configuration");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { issuer: string };
    expect(body.issuer).toBe("https://auth.test");
  });
});
