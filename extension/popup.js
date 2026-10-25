const enabledInput = document.getElementById('enabled');
const status = document.getElementById('status');
const count = document.getElementById('count');
const feed = document.getElementById('feed');

function showState(state) {
  enabledInput.checked = state.enabled !== false;
  status.textContent = state.enabled === false ? 'Protection paused.' : 'Protection enabled. Local checks only.';
  count.textContent = state.feedDomainCount ?? 0;
  if (state.syncError) feed.textContent = state.syncError;
  else feed.textContent = state.feedUpdatedAt ? `Synced ${new Date(state.feedUpdatedAt).toLocaleString()}.` : 'No phishing-feed domains have been synced yet.';
}

chrome.runtime.sendMessage({ type: 'get-protection-state' }).then(showState).catch((error) => { status.textContent = `Extension service error: ${error.message}`; });
enabledInput.addEventListener('change', () => chrome.runtime.sendMessage({ type: 'set-enabled', enabled: enabledInput.checked }).then(showState));
document.getElementById('sync').addEventListener('click', async (event) => {
  event.target.disabled = true; event.target.textContent = 'Syncing…';
  const result = await chrome.runtime.sendMessage({ type: 'sync-feed' });
  const state = await chrome.runtime.sendMessage({ type: 'get-protection-state' });
  showState({ ...state, syncError: result?.error || state.syncError });
  event.target.disabled = false; event.target.textContent = 'Sync local blocklist';
});
