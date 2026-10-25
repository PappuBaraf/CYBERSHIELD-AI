(() => {
  let enabled = true;
  chrome.storage.local.get(['enabled']).then((state) => { enabled = state.enabled !== false; });

  function showWarning(result, targetUrl, onProceed) {
    document.getElementById('cybershield-warning-root')?.remove();
    const host = document.createElement('div');
    host.id = 'cybershield-warning-root';
    host.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:rgba(2,7,14,.84);display:grid;place-items:center;font:14px system-ui;color:#eef5ff';
    const shadow = host.attachShadow({ mode: 'closed' });
    const box = document.createElement('section');
    box.style.cssText = 'box-sizing:border-box;width:min(560px,92vw);background:#101b28;border:1px solid #dc5864;border-radius:14px;padding:26px;box-shadow:0 24px 80px #000';
    const title = document.createElement('h2'); title.textContent = result?.verdict === 'known-phishing' ? 'Known phishing URL blocked' : 'CyberShield link warning';
    title.style.cssText = 'margin:0 0 10px;color:#ff929b';
    const text = document.createElement('p'); text.textContent = (result?.reasons || [result?.error || 'The local link-checking service could not be reached.']).join(' '); text.style.cssText = 'line-height:1.6;color:#c4d1e2';
    const address = document.createElement('code'); address.textContent = targetUrl; address.style.cssText = 'display:block;max-height:100px;overflow:auto;overflow-wrap:anywhere;background:#08111b;padding:10px;border-radius:6px;color:#f0c77b';
    const actions = document.createElement('div'); actions.style.cssText = 'display:flex;gap:10px;margin-top:18px';
    const back = document.createElement('button'); back.textContent = 'Back to safety';
    back.style.cssText = 'padding:10px 14px;background:#174337;color:#80eed0;border:1px solid #287960;border-radius:7px;cursor:pointer';
    back.onclick = () => host.remove();
    actions.append(back);
    if (onProceed) {
      const proceed = document.createElement('button'); proceed.textContent = 'Proceed anyway';
      proceed.style.cssText = 'padding:10px 14px;background:#332229;color:#ffb0b5;border:1px solid #78434a;border-radius:7px;cursor:pointer';
      proceed.onclick = () => { host.remove(); onProceed(); };
      actions.append(proceed);
    }
    box.append(title, text, address, actions); shadow.append(box); document.documentElement.append(host);
  }

  function checkLink(anchor, event) {
    if (!enabled || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || anchor.target === '_blank' || anchor.hasAttribute('download')) return;
    let target;
    try { target = new URL(anchor.href); } catch { return; }
    if (!['http:', 'https:'].includes(target.protocol) || target.href === location.href) return;
    event.preventDefault(); event.stopImmediatePropagation();
    const navigate = () => { location.assign(target.href); };
    chrome.runtime.sendMessage({ type: 'check-url', url: target.href }).then((reply) => {
      if (!reply?.ok) return showWarning({ reasons: [`Local link protection is unavailable: ${reply?.error || 'API not connected'}.`]}, target.href, navigate);
      if (reply.result.risk === 'high' || reply.result.verdict === 'known-phishing') showWarning(reply.result, target.href, navigate);
      else navigate();
    }).catch((error) => showWarning({ reasons: [`Could not contact local protection: ${error.message}`]}, target.href, navigate));
  }

  document.addEventListener('click', (event) => {
    const anchor = event.target instanceof Element ? event.target.closest('a[href]') : null;
    if (anchor) checkLink(anchor, event);
  }, true);

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === 'page-risk') showWarning(message.result, location.href, null);
  });
})();
