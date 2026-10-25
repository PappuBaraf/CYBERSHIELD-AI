const API = 'http://127.0.0.1:3001/api';
const RULE_BASE = 1000;

chrome.runtime.onInstalled.addListener(async () => {
  const settings = await chrome.storage.local.get(['enabled']);
  if (settings.enabled === undefined) await chrome.storage.local.set({ enabled: true });
  await syncBlocklist();
});

chrome.alarms.create('cybershield-feed-sync', { periodInMinutes: 30 });
chrome.alarms.onAlarm.addListener((alarm) => { if (alarm.name === 'cybershield-feed-sync') syncBlocklist(); });

async function syncBlocklist() {
  try {
    const { enabled } = await chrome.storage.local.get(['enabled']);
    if (enabled === false) {
      const oldRules = await chrome.declarativeNetRequest.getDynamicRules();
      const ownedIds = oldRules.filter((rule) => rule.id >= RULE_BASE && rule.id < RULE_BASE + 20).map((rule) => rule.id);
      await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: ownedIds, addRules: [] });
      await chrome.storage.local.set({ feedDomainCount: 0, syncError: '' });
      return { domains: 0, paused: true };
    }
    const response = await fetch(`${API}/url/blocklist`, { signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error(`Local API returned ${response.status}`);
    const data = await response.json();
    const domains = [...new Set((data.domains || []).filter((domain) => typeof domain === 'string' && /^[a-z0-9.-]+$/i.test(domain)))].slice(0, 20000);
    const rules = [];
    for (let offset = 0, index = 0; offset < domains.length; offset += 1000, index++) {
      rules.push({ id: RULE_BASE + index, priority: 10, action: { type: 'block' }, condition: { requestDomains: domains.slice(offset, offset + 1000), resourceTypes: ['main_frame'] } });
    }
    const old = await chrome.declarativeNetRequest.getDynamicRules();
    const owned = old.filter((rule) => rule.id >= RULE_BASE && rule.id < RULE_BASE + 20).map((rule) => rule.id);
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: owned, addRules: rules });
    await chrome.storage.local.set({ feedDomainCount: domains.length, feedUpdatedAt: data.fetchedAt || null, syncError: '' });
    return { domains: domains.length, fetchedAt: data.fetchedAt };
  } catch (error) {
    await chrome.storage.local.set({ syncError: `${error.message}. Keep the local dashboard running.` });
    return { error: error.message };
  }
}

async function checkUrl(url) {
  const response = await fetch(`${API}/url/check`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }), signal: AbortSignal.timeout(4000),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Local check returned ${response.status}`);
  return data;
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'check-url' && typeof message.url === 'string') {
    checkUrl(message.url).then((result) => sendResponse({ ok: true, result })).catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }
  if (message?.type === 'sync-feed') { syncBlocklist().then(sendResponse); return true; }
  if (message?.type === 'get-protection-state') {
    Promise.all([chrome.storage.local.get(['enabled', 'feedDomainCount', 'feedUpdatedAt', 'syncError']), chrome.declarativeNetRequest.getDynamicRules()])
      .then(([state, rules]) => sendResponse({ ...state, blockedRuleGroups: rules.filter((rule) => rule.id >= RULE_BASE && rule.id < RULE_BASE + 20).length }));
    return true;
  }
  if (message?.type === 'set-enabled') {
    const enabled = !!message.enabled;
    chrome.storage.local.set({ enabled }).then(async () => {
      const sync = await syncBlocklist();
      sendResponse({ enabled, ...sync });
    });
    return true;
  }
});

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0 || !/^https?:\/\//i.test(details.url)) return;
  const { enabled } = await chrome.storage.local.get(['enabled']);
  if (!enabled) return;
  try {
    const result = await checkUrl(details.url);
    if (result.risk === 'high' || result.verdict === 'known-phishing') {
      chrome.tabs.sendMessage(details.tabId, { type: 'page-risk', result }).catch(() => {});
    }
  } catch { /* Local API unavailable: leave navigation unchanged and show status in popup. */ }
});
