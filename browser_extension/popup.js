/**
 * PhishRadar Browser Extension — popup.js
 */

function escapeHtml(str) {
  const d = document.createElement("div");
  d.textContent = String(str ?? "");
  return d.innerHTML;
}

function truncateUrl(url, max = 55) {
  if (!url || url.length <= max) return url;
  return url.slice(0, max) + "…";
}

function riskClass(level) {
  return { high: "high", medium: "medium", safe: "safe" }[level] ?? "safe";
}

function riskLabel(level) {
  return {
    high:   "High risk of phishing",
    medium: "Potentially suspicious",
    safe:   "Likely safe",
  }[level] ?? "Unknown";
}

document.addEventListener("DOMContentLoaded", async () => {
  const urlDisplay = document.getElementById("url-display");
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    urlDisplay.textContent = truncateUrl(tab?.url ?? "Unknown");
  } catch {
    urlDisplay.textContent = "Could not read URL";
  }
});

document.getElementById("checkBtn").addEventListener("click", async () => {
  const statusArea = document.getElementById("statusArea");
  const btn        = document.getElementById("checkBtn");

  btn.disabled = true;
  statusArea.innerHTML = `
    <div class="loading-box">
      <svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83
                 M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
      </svg>
      Analysing URL…
    </div>
  `;

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const rawUrl = tab?.url ?? "";

    if (!rawUrl) {
      showError(statusArea, "Could not read the current tab URL.");
      btn.disabled = false;
      return;
    }

    if (rawUrl.startsWith("chrome://") || rawUrl.startsWith("chrome-extension://") || rawUrl.startsWith("about:")) {
      showError(statusArea, "Cannot scan internal browser pages.");
      btn.disabled = false;
      return;
    }

    const response = await fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: rawUrl }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      showError(statusArea, err.error ?? `Server error ${response.status}`);
      btn.disabled = false;
      return;
    }

    const data = await response.json();
    renderResult(statusArea, data, rawUrl);

  } catch (err) {
    showError(statusArea, "Cannot reach the PhishRadar API. Make sure app.py is running.");
  }

  btn.disabled = false;
});

function renderResult(container, data, rawUrl) {
  const level = riskClass(data.risk_level);
  const score = Math.round((data.score ?? 0) * 100);
  const label = riskLabel(data.risk_level);
  const reasonsHtml = (data.explanations ?? []).map(r => `<div class="reason">${escapeHtml(r)}</div>`).join("");

  container.innerHTML = `
    <div class="verdict ${escapeHtml(level)}">
      <div class="verdict-top">
        <span class="verdict-dot"></span>
        <span class="verdict-label">${escapeHtml(label)}</span>
        <span class="verdict-score">${escapeHtml(String(score))}%</span>
      </div>
      <div class="mini-bar-track">
        <div class="mini-bar-fill" style="width:0%" data-target="${escapeHtml(String(score))}%"></div>
      </div>
      <div class="reasons">${reasonsHtml}</div>
    </div>
    <a href="http://127.0.0.1:5000" target="_blank" class="open-full-btn">Open full analysis →</a>
    ${data.from_cache ? '<div style="text-align:center;font-size:0.68rem;color:var(--dim);margin-top:8px;">Cached result</div>' : ''}
  `;

  requestAnimationFrame(() => {
    const fill = container.querySelector(".mini-bar-fill");
    if (fill) setTimeout(() => { fill.style.width = fill.dataset.target; }, 50);
  });
}

function showError(container, message) {
  container.innerHTML = `<div class="error-box">${escapeHtml(message)}</div>`;
}
