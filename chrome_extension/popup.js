const backendInput = document.getElementById("backend-url");
const targetInput = document.getElementById("target-url");
const feedbackBox = document.getElementById("feedback");
const statusPill = document.getElementById("conn-status");
const chips = document.querySelectorAll(".chip");

let currentSiteId = null;
let currentDashboardUrl = null;

function getApiPrefix(baseUrl) {
  const clean = baseUrl.replace(/\/+$/, "");
  if (clean.includes(":8443")) {
    return {
      stats: `${clean}/mirage-shield/api/stats`,
      clone: `${clean}/mirage-shield/api/clone`,
      simulate: `${clean}/mirage-shield/api/simulate`,
      preview: `${clean}/mirage-shield/preview`,
      dashboard: `${clean}/mirage-shield/dashboard`,
      sites: `${clean}/mirage-shield/dashboard`,
    };
  }
  return {
    stats: `${clean}/api/shield/stats`,
    clone: `${clean}/api/shield/clone`,
    simulate: `${clean}/api/shield/simulate`,
    preview: `${clean}/api/shield/preview`,
    dashboard: `${clean}/sites`,
    sites: `${clean}/api/sites`,
  };
}

function getDomainSlug(rawUrl) {
  try {
    const parsed = new URL(rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`);
    return parsed.host.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48);
  } catch {
    return null;
  }
}

function buildSiteDashboardUrl(baseUrl, slug, targetUrl) {
  const qs = targetUrl ? `?target=${encodeURIComponent(targetUrl)}` : "";
  return `${baseUrl}/site/${slug}${qs}`;
}

function showFeedback(message, isError = false) {
  feedbackBox.textContent = message;
  feedbackBox.classList.remove("hidden", "error");
  if (isError) feedbackBox.classList.add("error");
}

function setActiveChip(url) {
  chips.forEach((chip) => {
    chip.classList.toggle("active", chip.dataset.url === url);
  });
}

async function refreshStats() {
  const baseUrl = backendInput.value.trim().replace(/\/+$/, "");
  const apis = getApiPrefix(baseUrl);
  const slug = currentSiteId || getDomainSlug(targetInput.value.trim());

  try {
    // Prefer site-isolated stats when protecting a specific website on main server
    if (!baseUrl.includes(":8443") && slug) {
      const siteRes = await fetch(`${baseUrl}/api/site/${slug}/stats`);
      if (siteRes.ok) {
        const sdata = await siteRes.json();
        currentSiteId = slug;
        currentDashboardUrl = `${baseUrl}/site/${slug}`;
        document.getElementById("stat-allowed").textContent = sdata.site?.total_absorbed ?? sdata.total_hits ?? 0;
        document.getElementById("stat-diverted").textContent = sdata.site?.fake_records_served ?? 0;
        document.getElementById("stat-blocked").textContent = sdata.ips_quarantined ?? 0;
        document.getElementById("stat-creds").textContent = sdata.creds_captured ?? 0;
        statusPill.textContent = "SITE ISOLATED";
        statusPill.classList.remove("offline");
        return;
      }
    }

    const res = await fetch(apis.stats);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    document.getElementById("stat-allowed").textContent = (data.redirected ?? 0) + (data.blocked ?? 0);
    document.getElementById("stat-diverted").textContent = data.fake_records_served ?? 0;
    document.getElementById("stat-blocked").textContent = data.blocked ?? 0;
    document.getElementById("stat-creds").textContent = data.credentials_captured ?? 0;

    statusPill.textContent = "ONLINE";
    statusPill.classList.remove("offline");
  } catch {
    statusPill.textContent = "OFFLINE";
    statusPill.classList.add("offline");
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  chrome.storage.local.get(["mirageBackendUrl"], (items) => {
    if (items.mirageBackendUrl) {
      backendInput.value = items.mirageBackendUrl;
      setActiveChip(items.mirageBackendUrl);
    }
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabUrl = tabs?.[0]?.url || "";
      if (tabUrl.startsWith("http://") || tabUrl.startsWith("https://")) {
        try {
          const parsed = new URL(tabUrl);
          targetInput.value = parsed.origin;
        } catch {
          targetInput.value = tabUrl;
        }
      }
      refreshStats();
    });
  });
});

chips.forEach((chip) => {
  chip.addEventListener("click", () => {
    const url = chip.dataset.url;
    backendInput.value = url;
    setActiveChip(url);
    chrome.storage.local.set({ mirageBackendUrl: url });
    refreshStats();
  });
});

backendInput.addEventListener("change", () => {
  const url = backendInput.value.trim().replace(/\/+$/, "");
  backendInput.value = url;
  setActiveChip(url);
  chrome.storage.local.set({ mirageBackendUrl: url });
  refreshStats();
});

document.getElementById("btn-clone").addEventListener("click", async () => {
  const btn = document.getElementById("btn-clone");
  const targetUrl = targetInput.value.trim();
  const baseUrl = backendInput.value.trim().replace(/\/+$/, "");
  if (!targetUrl) {
    showFeedback("Enter a website URL to protect.", true);
    return;
  }

  const apis = getApiPrefix(baseUrl);
  btn.disabled = true;
  btn.textContent = "⏳ Provisioning site shield...";

  try {
    const res = await fetch(apis.clone, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: targetUrl, max_pages: 2 }),
    });
    const data = await res.json();
    if (res.ok && data.success) {
      if (data.site_id) {
        currentSiteId = data.site_id;
        currentDashboardUrl = buildSiteDashboardUrl(baseUrl, data.site_id, data.target_url || targetUrl);
      }
      showFeedback(`✅ Isolated Shield active for ${data.target_url}`);
      await refreshStats();
      if (currentDashboardUrl) {
        chrome.tabs.create({ url: currentDashboardUrl });
      }
    } else {
      showFeedback(`❌ ${data.error || "Provision failed"}`, true);
    }
  } catch {
    showFeedback("❌ Server unreachable. Check MIRAGE Server URL.", true);
  } finally {
    btn.disabled = false;
    btn.textContent = "🛡️ Protect Site & Open Its Dashboard";
  }
});

document.getElementById("btn-sim-attack").addEventListener("click", async () => {
  const baseUrl = backendInput.value.trim().replace(/\/+$/, "");
  const slug = currentSiteId || getDomainSlug(targetInput.value.trim());
  try {
    if (baseUrl.includes(":8443")) {
      const simRes = await fetch(`${baseUrl}/mirage-shield/api/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario: "sqli" }),
      });
      const sdata = await simRes.json();
      showFeedback(`🚨 Proxy ${sdata.decision || "TESTED"} (score ${sdata.score ?? 0})`);
      refreshStats();
      return;
    }
    if (!slug) {
      showFeedback("Enter a customer website URL first.", true);
      return;
    }
    const regRes = await fetch(`${baseUrl}/api/sites/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: targetInput.value.trim() }),
    });
    if (regRes.ok) {
      const reg = await regRes.json();
      const activeSlug = reg.site_id || slug;
      currentSiteId = activeSlug;
      currentDashboardUrl = buildSiteDashboardUrl(baseUrl, activeSlug, targetInput.value.trim());
      const testRes = await fetch(`${baseUrl}/api/site/${activeSlug}/test-absorb`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind: "sqli" }),
      });
      const tdata = await testRes.json();
      showFeedback(`🚨 Absorbed SQLi & served ${tdata.fake_records_served ?? 0} fake records!`);
      refreshStats();
      return;
    }
    showFeedback("❌ Could not register site for test probe.", true);
  } catch {
    showFeedback("❌ Could not reach MIRAGE Shield server.", true);
  }
});

document.getElementById("btn-preview").addEventListener("click", () => {
  const baseUrl = backendInput.value.trim().replace(/\/+$/, "");
  const apis = getApiPrefix(baseUrl);
  const targetUrl = targetInput.value.trim();
  if (!apis.preview.includes(":8443") && targetUrl) {
    try {
      const host = new URL(targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`).host;
      chrome.tabs.create({ url: `${baseUrl}/portal/${host}` });
      return;
    } catch {}
  }
  chrome.tabs.create({ url: apis.preview });
});

document.getElementById("btn-dashboard").addEventListener("click", () => {
  const baseUrl = backendInput.value.trim().replace(/\/+$/, "");
  const apis = getApiPrefix(baseUrl);
  if (currentDashboardUrl) {
    chrome.tabs.create({ url: currentDashboardUrl });
    return;
  }
  const slug = getDomainSlug(targetInput.value.trim());
  if (!baseUrl.includes(":8443") && slug) {
    chrome.tabs.create({ url: buildSiteDashboardUrl(baseUrl, slug, targetInput.value.trim()) });
    return;
  }
  chrome.tabs.create({ url: apis.dashboard });
});
