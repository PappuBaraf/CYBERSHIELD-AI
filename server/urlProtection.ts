export type UrlFeed = { provider: string; fetchedAt: string | null; updateIntervalHours: number; acceptedTermsAt?: string | null; urls: string[] };

const brandDomains = ["paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com", "instagram.com", "github.com", "netflix.com", "coinbase.com"];
const shorteners = new Set(["bit.ly", "tinyurl.com", "t.co", "is.gd", "lnkd.in"]);
const sharedHostingRoots = ["pages.dev", "vercel.app", "netlify.app", "github.io", "weebly.com", "blogspot.com", "s3.amazonaws.com", "web.app", "workers.dev", "cloudfront.net"];
const dangerousFile = /\.(?:exe|msi|scr|bat|cmd|ps1|vbs|js|hta)(?:$|[?#])/i;
export function isSharedHostingHost(hostname: string) { return sharedHostingRoots.some((root) => hostname === root || hostname.endsWith(`.${root}`)); }

function feedMatch(url: URL, feed: UrlFeed) {
  const normalized = `${url.origin}${url.pathname}${url.search}`.replace(/\/$/, "").toLowerCase();
  return feed.urls.find((entry) => {
    try {
      const listed = new URL(entry);
      const listedFull = `${listed.origin}${listed.pathname}${listed.search}`.replace(/\/$/, "").toLowerCase();
      const sharedHost = isSharedHostingHost(listed.hostname);
      return listedFull === normalized || (!sharedHost && url.hostname === listed.hostname);
    } catch { return false; }
  });
}

export function checkUrl(rawUrl: string, feed: UrlFeed) {
  if (typeof rawUrl !== "string" || rawUrl.length > 4096) throw new Error("URL must be text no longer than 4096 characters.");
  let url: URL;
  try { url = new URL(rawUrl.trim()); } catch { throw new Error("Enter a complete valid URL, including http:// or https://."); }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS links can be checked.");
  if (url.username || url.password) return { url: url.href, host: url.hostname, verdict: "suspicious", risk: "high", score: 85, reasons: ["The address contains embedded username or password text, which can disguise the destination."], matchedFeed: false, source: "Local URL heuristics" };

  const hit = feedMatch(url, feed);
  if (hit) return { url: url.href, host: url.hostname, verdict: "known-phishing", risk: "high", score: 100, reasons: ["This URL or hostname exactly matches the locally refreshed OpenPhish community feed."], matchedFeed: true, source: "OpenPhish community feed", matchedEntry: hit };

  let score = 0;
  const reasons: string[] = [];
  const host = url.hostname.toLowerCase();
  if (host.startsWith("xn--") || host.split(".").some((label) => label.startsWith("xn--"))) { score += 25; reasons.push("Internationalized/punycode hostname; inspect the displayed domain carefully."); }
  const baseDomain = host.split(".").slice(-2).join(".");
  const brand = brandDomains.find((known) => host.includes(known.split(".")[0]) && baseDomain !== known);
  if (brand && /login|signin|verify|account|secure|payment|wallet/i.test(`${host}${url.pathname}`)) { score += 55; reasons.push(`Brand-like login wording appears outside the official ${brand} domain.`); }
  if (dangerousFile.test(url.pathname)) { score += 35; reasons.push("The link points to a script or executable file type."); }
  if (shorteners.has(host)) { score += 15; reasons.push("The shortened link hides its final destination."); }
  if (url.protocol === "http:") { score += 10; reasons.push("The link does not use HTTPS."); }
  const verdict = score >= 50 ? "suspicious" : score >= 20 ? "review" : "no-known-match";
  const risk = score >= 50 ? "high" : score >= 20 ? "medium" : "low";
  if (!reasons.length) reasons.push("No local feed match or configured heuristic triggered. This does not prove the site is safe.");
  return { url: url.href, host, verdict, risk, score: Math.min(score, 99), reasons, matchedFeed: false, source: "Local URL heuristics" };
}
