import { test } from "node:test";
import assert from "node:assert/strict";
import { checkUrl, isSharedHostingHost, type UrlFeed } from "../server/urlProtection.js";

const emptyFeed: UrlFeed = { provider: "OpenPhish community feed", fetchedAt: null, updateIntervalHours: 12, urls: [] };

test("URL checker flags deceptive credential URLs and stays local", () => {
  const result = checkUrl("https://paypal-login-security.example/account", emptyFeed);
  assert.equal(result.verdict, "suspicious");
  assert.equal(result.risk, "high");
  assert.ok(result.reasons.some((reason) => reason.includes("official paypal.com")));
});

test("URL checker matches an exact threat-feed URL and host", () => {
  const feed = { ...emptyFeed, urls: ["https://phish.example/login?case=1"] };
  assert.equal(checkUrl("https://phish.example/login?case=1", feed).verdict, "known-phishing");
  assert.equal(checkUrl("https://phish.example/another-path", feed).verdict, "known-phishing");
});

test("URL checker avoids broad matches for shared hosting and reports unknown as not safe", () => {
  const feed = { ...emptyFeed, urls: ["https://bad-site.pages.dev/login"] };
  assert.equal(isSharedHostingHost("bad-site.pages.dev"), true);
  assert.equal(checkUrl("https://good-site.pages.dev/", feed).verdict, "no-known-match");
  assert.match(checkUrl("https://example.com/", emptyFeed).reasons[0], /does not prove/);
});

test("URL checker rejects unsupported schemes and malformed URLs", () => {
  assert.throws(() => checkUrl("javascript:alert(1)", emptyFeed), /Only HTTP and HTTPS/);
  assert.throws(() => checkUrl("not a URL", emptyFeed), /complete valid URL/);
});
