const backendInput = document.getElementById("backend-url");
const targetInput = document.getElementById("target-url");
const feedbackBox = document.getElementById("feedback");
const statusPill = document.getElementById("conn-status");
const chips = document.querySelectorAll(".chip");

function getApiPrefix(baseUrl) {
  const clean = baseUrl.replace(/\/+$/, "");
  // Standalone proxy on :8443 mounts endpoints under /mirage-shield/*
  if (clean.includes(":8443")) {
    return {
      stats: `${clean}/mirage-shield/api/stats`,
      clone: `${clean}/mirage-shield/api/clone`,
      simulate: `${clean}/mirage-shield/api/simulate`,
      preview: `${clean}/mirage-shield/preview`,
      dashboard: `${clean}/mirage-shield/dashboard`,
    };
  }
  // Main dashboard (:5000) and Vercel site mount under /api/shield/*
  return {
    stats: `${clean}/api/shield/stats`,
    clone: `${clean}/api/shield/clone`,
    simulate: `${clean}/api/shield/simulate`,
    preview: `${clean}/api/shield/preview`,
    dashboard: `${clean}/shield`,
  };
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
  const apis = getApiPrefix(backendInput.value.trim());
  try {
    const res = await fetch(apis.stats);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    document.getElementById("stat-allowed").textContent = data.allowed ?? 0;
    document.getElementById("stat-diverted").textContent = data.redirected ?? 0;
    document.getElementById("stat-blocked").textContent = data.blocked ?? 0;
    document.getElementById("stat-creds").textContent = data.credentials_captured ?? 0;

    statusPill.textContent = "ONLINE";
    statusPill.classList.remove("offline");
  } catch (err) {
    statusPill.textContent = "OFFLINE";
    statusPill.classList.add("offline");
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  // Restore saved backend URL
  chrome.storage.local.get(["mirageBackendUrl"], (items) => {
    if (items.mirageBackendUrl) {
      backendInput.value = items.mirageBackendUrl;
      setActiveChip(items.mirageBackendUrl);
    }
    refreshStats();
  });

  // Read active browser tab URL automatically
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
  if (!targetUrl) {
    showFeedback("Enter a website URL to clone.", true);
    return;
  }

  const apis = getApiPrefix(backendInput.value.trim());
  btn.disabled = true;
  btn.textContent = "⏳ Cloning website into honeypot...";

  try {
    const res = await fetch(apis.clone, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: targetUrl, max_pages: 3 }),
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showFeedback(`✅ Honeypot clone active for ${data.target_url}`);
      refreshStats();
    } else {
      showFeedback(`❌ ${data.error || "Clone failed"}`, true);
    }
  } catch (err) {
    showFeedback("❌ Server unreachable. Check MIRAGE Server URL or push latest update.", true);
  } finally {
    btn.disabled = false;
    btn.textContent = "🪞 Create Honeypot Clone & Protect";
  }
});

document.getElementById("btn-sim-attack").addEventListener("click", async () => {
  const apis = getApiPrefix(backendInput.value.trim());
  try {
    const res = await fetch(apis.simulate, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: "sqli" }),
    });
    const data = await res.json();
    showFeedback(`⚡ ${data.ip} → ${data.decision} (Score ${data.score}/100)`);
    refreshStats();
  } catch {
    showFeedback("❌ Could not reach MIRAGE Shield API.", true);
  }
});

document.getElementById("btn-preview").addEventListener("click", () => {
  const apis = getApiPrefix(backendInput.value.trim());
  const targetUrl = targetInput.value.trim();
  const previewUrl = targetUrl && !apis.preview.includes(":8443")
    ? `${apis.preview}?target=${encodeURIComponent(targetUrl)}`
    : apis.preview;
  chrome.tabs.create({ url: previewUrl });
});

document.getElementById("btn-dashboard").addEventListener("click", () => {
  const apis = getApiPrefix(backendInput.value.trim());
  chrome.tabs.create({ url: apis.dashboard });
});
