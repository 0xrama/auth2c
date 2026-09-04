import { describe, it, expect } from "vitest";
import {
  appOrigin,
  audienceForOrigin,
  base64urlDecode,
  originFromAudience,
  pairwiseSubject,
  parseVerifiedClaims,
  randomToken,
  sha256,
  timingSafeEqual,
  validatePkceRequest,
} from "../src/index.js";

describe("appOrigin / redirect validation", () => {
  it("allows HTTPS origins", () => {
    expect(appOrigin("https://app.test/cb")).toBe("https://app.test");
    expect(appOrigin("https://app.test:8443/path?q=1")).toBe("https://app.test:8443");
  });

  it("allows loopback HTTP for local development", () => {
    expect(appOrigin("http://localhost:3000/cb")).toBe("http://localhost:3000");
    expect(appOrigin("http://127.0.0.1:8080/")).toBe("http://127.0.0.1:8080");
  });

  it("rejects remote HTTP", () => {
    expect(() => appOrigin("http://evil.test/cb")).toThrow(/HTTPS/);
  });

  it("rejects credentials and fragments", () => {
    expect(() => appOrigin("https://u:p@app.test/cb")).toThrow(/Invalid redirect_uri/);
    expect(() => appOrigin("https://app.test/cb#frag")).toThrow(/Invalid redirect_uri/);
  });
});

describe("base64url", () => {
  it("round-trips bytes", () => {
    const input = new TextEncoder().encode("hello world");
    const enc = Buffer.from(input).toString("base64url");
    const dec = base64urlDecode(enc);
    expect(dec).toEqual(input);
  });
});

describe("sha256 / randomToken", () => {
  it("hashes PKCE verifier as base64url", async () => {
    expect(await sha256("abc")).toBe("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
  });

  it("produces random tokens of expected length", () => {
    const a = randomToken(32);
    const b = randomToken(32);
    expect(a).not.toBe(b);
    expect(a.length).toBeGreaterThan(40);
  });
});

describe("pairwiseSubject", () => {
  it("scopes identities by origin", async () => {
    const a = await pairwiseSubject("secret", "user", "https://a.test");
    const b = await pairwiseSubject("secret", "user", "https://b.test");
    expect(a).not.toBe(b);
    expect(a).toBe(await pairwiseSubject("secret", "user", "https://a.test"));
    expect(a.startsWith("pw_")).toBe(true);
  });

  it("is keyed by the pairwise secret", async () => {
    const a = await pairwiseSubject("s1", "user", "https://a.test");
    const b = await pairwiseSubject("s2", "user", "https://a.test");
    expect(a).not.toBe(b);
  });

  it("never leaks the raw provider subject", async () => {
    const s = await pairwiseSubject("secret", "provider-sub-123", "https://a.test");
    expect(s).not.toContain("provider-sub-123");
  });
});

describe("audience construction / parsing", () => {
  it("builds and parses origin audiences", () => {
    expect(audienceForOrigin("https://app.test")).toBe("origin:https://app.test");
    expect(originFromAudience("origin:https://app.test")).toBe("https://app.test");
  });

  it("rejects array and malformed audiences", () => {
    expect(() => originFromAudience(["https://a", "https://b"])).toThrow();
    expect(() => originFromAudience("https://app.test")).toThrow();
    expect(() => originFromAudience("origin:")).toThrow();
    expect(() => originFromAudience(null)).toThrow();
  });
});

describe("parseVerifiedClaims", () => {
  const good = {
    sub: "pw_x",
    aud: "origin:https://app.test",
    jti: "sess-1",
    iat: 1000,
    exp: 2000,
  };

  it("parses a well-formed claim set", () => {
    expect(parseVerifiedClaims(good)).toEqual(good);
  });

  it("rejects array audience", () => {
    expect(() => parseVerifiedClaims({ ...good, aud: ["a", "b"] })).toThrow(/audience must be scalar/);
  });

  it("rejects missing/invalid scalar fields", () => {
    expect(() => parseVerifiedClaims({ ...good, sub: "" })).toThrow(/sub/);
    expect(() => parseVerifiedClaims({ ...good, jti: 5 })).toThrow(/jti/);
    expect(() => parseVerifiedClaims({ ...good, exp: NaN })).toThrow(/exp/);
  });
});

describe("timingSafeEqual", () => {
  it("matches equal strings", async () => {
    expect(await timingSafeEqual("abc", "abc")).toBe(true);
  });

  it("rejects differing strings", async () => {
    expect(await timingSafeEqual("abc", "abd")).toBe(false);
    expect(await timingSafeEqual("abc", "abcd")).toBe(false);
    expect(await timingSafeEqual("abc", "")).toBe(false);
  });
});

describe("validatePkceRequest", () => {
  it("accepts a valid S256 request and returns origin", () => {
    const { origin, redirectUri } = validatePkceRequest({
      redirect_uri: "https://app.test/cb",
      code_challenge: "x".repeat(43),
      code_challenge_method: "S256",
      state: "s".repeat(16),
    });
    expect(origin).toBe("https://app.test");
    expect(redirectUri).toBe("https://app.test/cb");
  });

  it("rejects short challenge / wrong method / short state", () => {
    const base = {
      redirect_uri: "https://app.test/cb",
      code_challenge: "x".repeat(43),
      code_challenge_method: "S256",
      state: "s".repeat(16),
    };
    expect(() => validatePkceRequest({ ...base, code_challenge: "short" })).toThrow();
    expect(() => validatePkceRequest({ ...base, code_challenge_method: "plain" })).toThrow();
    expect(() => validatePkceRequest({ ...base, state: "short" })).toThrow();
    expect(() => validatePkceRequest({ ...base, redirect_uri: "http://evil.test/cb" })).toThrow();
  });
});
