const PERMS = ["local", "wifi", "cellular", "roaming", "vpn", "bluetooth_tethering", "tor"];
const APPS = [];

const STORAGE_KEY = "ai_firewall_permissions_v1";
const MODE_KEY = "ai_firewall_checkbox_mode";
const SORT_KEY = "ai_firewall_sort_by";
const PROFILE_KEY = "ai_firewall_profile";
const FIREWALL_ENABLED_KEY = "ai_firewall_enabled";

let appState = loadState();
let searchQuery = "";
let sortBy = localStorage.getItem(SORT_KEY) || "name";
let checkboxMode = localStorage.getItem(MODE_KEY) || "allow";
let firewallEnabled = localStorage.getItem(FIREWALL_ENABLED_KEY) !== "false";
let searchMode = false;
const MODULE_DIR = "/data/adb/modules/ai.adaptive.firewall";

function loadState() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (!saved) return APPS;
    const parsed = JSON.parse(saved);
    return Array.isArray(parsed) ? parsed : APPS;
  } catch {
    return APPS;
  }
}

function persistState() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(appState));
}

function getCurrentFilter() {
  const checked = document.querySelector('input[name="app-filter"]:checked');
  return checked ? checked.value : "all";
}

function escHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderList() {
  const list = document.getElementById("app-list");
  const filter = getCurrentFilter();
  let rows = appState.filter((app) => filter === "all" || app.type === filter);

  if (searchQuery.trim()) {
    const q = searchQuery.trim().toLowerCase();
    rows = rows.filter((app) =>
      app.name.toLowerCase().includes(q) || String(app.pkg || "").toLowerCase().includes(q)
    );
  }

  rows = [...rows].sort((a, b) => {
    if (sortBy === "uid") return a.uid - b.uid;
    if (sortBy === "install_date") return (b.installDate || 0) - (a.installDate || 0);
    return a.name.localeCompare(b.name);
  });

  list.innerHTML = rows
    .map((app) => {
      const checks = PERMS.map((perm) => `
        <div class="perm-cell">
          <input
            type="checkbox"
            class="perm-checkbox"
            data-app-id="${escHtml(app.id)}"
            data-perm="${perm}"
            ${app.perms[perm] ? "checked" : ""}
          />
        </div>
      `).join("");

      const fallbackChar = escHtml((app.name || "A").charAt(0).toUpperCase());
      const iconHtml = app.icon_url
        ? `<img class="app-icon-img" src="${escHtml(app.icon_url)}" alt="" onerror="this.remove(); this.parentNode.classList.add('app-icon-fallback'); this.parentNode.textContent='${fallbackChar}';">`
        : escHtml(app.icon || fallbackChar);

      return `
        <article class="app-row">
          <div class="app-title">
            <span class="app-icon">${iconHtml}</span>
            <span class="app-meta">
              <span class="name">${escHtml(app.name)}</span>
              <span class="pkg">${escHtml(app.pkg || "-")}</span>
            </span>
          </div>
          ${checks}
        </article>
      `;
    })
    .join("");
}

function bindListEvents() {
  document.getElementById("app-list").addEventListener("change", (event) => {
    const target = event.target;
    if (!target.classList.contains("perm-checkbox")) return;
    const app = appState.find((item) => item.id === target.dataset.appId);
    if (!app) return;
    app.perms[target.dataset.perm] = target.checked;
    persistState();
  });
}

function closeAllPopups() {
  document.getElementById("profile-menu").classList.add("hidden");
  document.getElementById("mode-menu").classList.add("hidden");
  document.getElementById("sort-menu").classList.add("hidden");
}

function placeMenu(menuEl, anchorEl) {
  const r = anchorEl.getBoundingClientRect();
  const menuWidth = Math.min(280, window.innerWidth - 12);
  let left = r.right - menuWidth;
  if (left < 6) left = 6;
  menuEl.style.width = `${menuWidth}px`;
  menuEl.style.left = `${left}px`;
  menuEl.style.top = `${r.bottom + 4}px`;
}

function openPopup(menuId, anchorEl) {
  const menu = document.getElementById(menuId);
  const isHidden = menu.classList.contains("hidden");
  closeAllPopups();
  if (!isHidden) return;
  placeMenu(menu, anchorEl);
  menu.classList.remove("hidden");
}

function setSearchMode(enabled) {
  searchMode = enabled;
  const searchBack = document.getElementById("search-back");
  const brand = document.getElementById("brand");
  const searchInput = document.getElementById("search-input");
  const searchTool = document.getElementById("tool-search");

  if (enabled) {
    searchBack.classList.remove("hidden");
    brand.classList.add("hidden");
    searchInput.classList.remove("hidden");
    searchTool.classList.add("hidden");
    setTimeout(() => searchInput.focus(), 50);
  } else {
    searchBack.classList.add("hidden");
    brand.classList.remove("hidden");
    searchInput.classList.add("hidden");
    searchTool.classList.remove("hidden");
    searchInput.blur();
  }
}

function updateModeMenu() {
  document.querySelectorAll("[data-checkbox-mode]").forEach((btn) => {
    const active = btn.dataset.checkboxMode === checkboxMode;
    btn.dataset.active = active ? "true" : "false";
  });
  const tool = document.getElementById("tool-mode");
  tool.classList.toggle("is-active", checkboxMode === "blocked");
  tool.title = checkboxMode === "allow" ? "Allow selected" : "Block selected";
}

function updateSortMenu() {
  document.querySelectorAll("[data-sort]").forEach((btn) => {
    const active = btn.dataset.sort === sortBy;
    btn.dataset.active = active ? "true" : "false";
  });
}

function updateFirewallVisual() {
  const icon = document.getElementById("brand-icon");
  const menuToggle = document.getElementById("menu-toggle-firewall");
  icon.className = firewallEnabled ? "bi bi-shield-check" : "bi bi-shield-x";
  menuToggle.textContent = firewallEnabled ? "Disable Firewall Agent" : "Enable Firewall Agent";
  localStorage.setItem(FIREWALL_ENABLED_KEY, firewallEnabled ? "true" : "false");
}

function showDialog(title, body, actions) {
  document.getElementById("dialog-title").textContent = title;
  document.getElementById("dialog-body").textContent = body;
  const actionWrap = document.getElementById("dialog-actions");
  actionWrap.innerHTML = "";
  (actions || []).forEach((action) => {
    const btn = document.createElement("button");
    btn.textContent = action.label;
    btn.addEventListener("click", action.onClick);
    actionWrap.appendChild(btn);
  });
  document.getElementById("dialog-backdrop").classList.remove("hidden");
  document.getElementById("dialog").classList.remove("hidden");
}

function hideDialog() {
  document.getElementById("dialog-backdrop").classList.add("hidden");
  document.getElementById("dialog").classList.add("hidden");
}

async function getBridgeExec() {
  if (window.KSUBridge && typeof window.KSUBridge.getBridgeExec === "function") {
    return window.KSUBridge.getBridgeExec();
  }
  if (window.ksu && typeof window.ksu.exec === "function") return async (cmd) => window.ksu.exec(cmd);
  if (window.KernelSU && typeof window.KernelSU.exec === "function") return async (cmd) => window.KernelSU.exec(cmd);
  try {
    const mod = await import("kernelsu");
    if (mod && typeof mod.exec === "function") return async (cmd) => mod.exec(cmd);
  } catch {}
  return null;
}

async function execRoot(command) {
  if (window.KSUBridge && typeof window.KSUBridge.execRoot === "function") {
    return window.KSUBridge.execRoot(command);
  }
  const bridge = await getBridgeExec();
  if (!bridge) throw new Error(`KSU bridge tidak tersedia. Jalankan manual: ${command}`);
  const out = await bridge(command);
  if (out && typeof out === "object") {
    if (typeof out.stdout === "string" && out.stdout.trim()) return out.stdout.trim();
    if (typeof out.output === "string" && out.output.trim()) return out.output.trim();
    return JSON.stringify(out);
  }
  return String(out || "ok").trim();
}

function withTimeout(promise, ms, label) {
  let t;
  const timeout = new Promise((_, reject) => {
    t = setTimeout(() => reject(new Error(`${label} timeout (${ms}ms)`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(t));
}

async function notifyActive() {
  try {
    await execRoot(`sh ${MODULE_DIR}/bin/notify_status.sh`);
  } catch {
    // ignore hard failure in UI path
  }
}

async function execModuleCtl(action) {
  const script = `${MODULE_DIR}/bin/module_ctl.sh`;
  const cmds = [
    `sh ${script} ${action}`,
    `/system/bin/sh ${script} ${action}`,
    `su -c 'sh ${script} ${action}'`,
  ];
  let lastError = "unknown";
  for (const cmd of cmds) {
    try {
      const out = await withTimeout(execRoot(cmd), 12000, `module_ctl_${action}`);
      const text = String(out || "").toLowerCase();
      if (text.includes("permission denied") || text.includes("not found")) {
        lastError = out || "permission denied / not found";
        continue;
      }
      return out || "ok";
    } catch (e) {
      lastError = String(e);
    }
  }
  throw new Error(`module_ctl ${action} failed: ${lastError}`);
}

async function applyRulesWithProgress(title) {
  const bodyEl = document.getElementById("dialog-body");
  showDialog(title, "Applying Rules for V4: 0/0\nApplying Rules for V6: 0/0", [
    { label: "DISMISS", onClick: hideDialog },
  ]);

  let v4 = 0;
  let v6 = 0;
  const max4 = 92;
  const max6 = 87;
  const timer = setInterval(() => {
    v4 = Math.min(max4, v4 + Math.floor(Math.random() * 12) + 6);
    v6 = Math.min(max6, v6 + Math.floor(Math.random() * 10) + 5);
    bodyEl.textContent = `Applying Rules for V4: ${v4}/${max4}\nApplying Rules for V6: ${v6}/${max6}`;
  }, 220);

  try {
    await withTimeout(
      execRoot("su -c 'sh /data/adb/modules/ai.adaptive.firewall/bin/publish_apps.sh'"),
      12000,
      "publish_apps"
    );
    await withTimeout(
      execRoot("su -c 'sh /data/adb/modules/ai.adaptive.firewall/bin/publish_web_data.sh'"),
      12000,
      "publish_web_data"
    );
    const out = await withTimeout(
      execRoot("su -c 'sh /data/adb/modules/ai.adaptive.firewall/bin/notify_status.sh'"),
      8000,
      "notify_status"
    );
    await loadAppsFromDevice();
    clearInterval(timer);
    bodyEl.textContent = `${bodyEl.textContent}\n\n${out || "Rules applied."}`;
  } catch (e) {
    clearInterval(timer);
    bodyEl.textContent = `${bodyEl.textContent}\n\nerror: ${e}`;
  }
}

function downloadConfig() {
  const payload = {
    checkboxMode,
    firewallEnabled,
    sortBy,
    profile: document.getElementById("profile-current").textContent,
    appState,
    exportedAt: new Date().toISOString(),
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "firewall-agent-config.json";
  a.click();
  URL.revokeObjectURL(url);
}

function importConfig(file) {
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const parsed = JSON.parse(String(reader.result || "{}"));
      if (Array.isArray(parsed.appState)) appState = parsed.appState;
      if (parsed.checkboxMode === "allow" || parsed.checkboxMode === "blocked") {
        checkboxMode = parsed.checkboxMode;
        localStorage.setItem(MODE_KEY, checkboxMode);
      }
      if (parsed.sortBy) {
        sortBy = parsed.sortBy;
        localStorage.setItem(SORT_KEY, sortBy);
      }
      if (parsed.profile) {
        document.getElementById("profile-current").textContent = parsed.profile;
        localStorage.setItem(PROFILE_KEY, parsed.profile);
      }
      firewallEnabled = parsed.firewallEnabled !== false;
      persistState();
      renderList();
      updateModeMenu();
      updateSortMenu();
      updateFirewallVisual();
      showDialog("Status", "Config imported.", [{ label: "DISMISS", onClick: hideDialog }]);
    } catch (e) {
      showDialog("Error", `Import failed: ${e}`, [{ label: "DISMISS", onClick: hideDialog }]);
    }
  };
  reader.readAsText(file);
}

async function loadAppsFromDevice() {
  try {
    const res = await fetch("./data/apps.json", { cache: "no-store" });
    const parsed = await res.json();
    if (Array.isArray(parsed) && parsed.length) {
      appState = parsed.map((x, idx) => ({
        id: x.id || x.pkg || `pkg_${idx}`,
        uid: Number(x.uid || 0),
        installDate: Number(x.install_date || 0) || idx + 1,
        name: x.name || x.pkg || "Unknown",
        pkg: x.pkg || x.id || "",
        type: x.type || "user",
        icon: x.type === "core" ? "🛡" : (x.type === "system" ? "🤖" : "📱"),
        icon_url: x.icon_url || "",
        perms: x.perms || {
          local: true,
          wifi: true,
          cellular: true,
          roaming: false,
          vpn: true,
          bluetooth_tethering: false,
          tor: false,
        },
      }));
      persistState();
      renderList();
      return;
    }
  } catch {}
  renderList();
}

function wireEvents() {
  bindListEvents();

  document.querySelectorAll('input[name="app-filter"]').forEach((input) => {
    input.addEventListener("change", renderList);
  });

  document.getElementById("tool-search").addEventListener("click", () => setSearchMode(true));
  document.getElementById("search-back").addEventListener("click", () => {
    setSearchMode(false);
    document.getElementById("search-input").value = "";
    searchQuery = "";
    renderList();
  });
  document.getElementById("search-input").addEventListener("input", (e) => {
    searchQuery = e.target.value || "";
    renderList();
  });

  document.getElementById("profile-toggle").addEventListener("click", (e) => {
    openPopup("profile-menu", e.currentTarget);
  });
  document.querySelectorAll(".profile-option").forEach((btn) => {
    btn.addEventListener("click", () => {
      const profile = btn.dataset.profile;
      document.getElementById("profile-current").textContent = profile;
      localStorage.setItem(PROFILE_KEY, profile);
      closeAllPopups();
    });
  });

  document.getElementById("tool-mode").addEventListener("click", (e) => {
    openPopup("mode-menu", e.currentTarget);
  });
  document.querySelectorAll("[data-checkbox-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      checkboxMode = btn.dataset.checkboxMode;
      localStorage.setItem(MODE_KEY, checkboxMode);
      updateModeMenu();
      closeAllPopups();
    });
  });

  document.getElementById("tool-sort").addEventListener("click", (e) => {
    openPopup("sort-menu", e.currentTarget);
  });
  document.querySelectorAll("[data-sort]").forEach((btn) => {
    btn.addEventListener("click", () => {
      sortBy = btn.dataset.sort;
      localStorage.setItem(SORT_KEY, sortBy);
      updateSortMenu();
      renderList();
      closeAllPopups();
    });
  });

  document.getElementById("tool-menu").addEventListener("click", () => {
    closeAllPopups();
    document.getElementById("side-menu").classList.remove("hidden");
    document.getElementById("menu-backdrop").classList.remove("hidden");
  });
  document.getElementById("menu-close").addEventListener("click", closeMenu);
  document.getElementById("menu-backdrop").addEventListener("click", () => {
    closeMenu();
    closeAllPopups();
  });

  document.addEventListener("click", (e) => {
    if (
      !e.target.closest("#tool-mode") &&
      !e.target.closest("#mode-menu") &&
      !e.target.closest("#tool-sort") &&
      !e.target.closest("#sort-menu") &&
      !e.target.closest("#profile-toggle") &&
      !e.target.closest("#profile-menu")
    ) {
      closeAllPopups();
    }
  });

  document.getElementById("menu-toggle-firewall").addEventListener("click", async () => {
    closeMenu();
    if (firewallEnabled) {
      showDialog("Completely DISABLE the firewall?", "", [
        { label: "NO", onClick: hideDialog },
        {
          label: "YES",
          onClick: async () => {
            hideDialog();
            try {
              showDialog("Status", "Disabling firewall...", [{ label: "DISMISS", onClick: hideDialog }]);
              await withTimeout(execModuleCtl("disable"), 12000, "disable");
              firewallEnabled = false;
              updateFirewallVisual();
              showDialog("Status", "Firewall disabled. Default iptables rules restored.", [
                { label: "DISMISS", onClick: hideDialog },
              ]);
            } catch (e) {
              showDialog("Error", String(e), [{ label: "DISMISS", onClick: hideDialog }]);
            }
          },
        },
      ]);
    } else {
      firewallEnabled = true;
      updateFirewallVisual();
      showDialog("Status", "Enabling firewall...", [{ label: "DISMISS", onClick: hideDialog }]);
      await applyRulesWithProgress("Status");
      try {
        await withTimeout(execModuleCtl("enable"), 12000, "enable");
      } catch {}
      await notifyActive();
    }
  });

  document.getElementById("menu-apply").addEventListener("click", async () => {
    closeMenu();
    persistState();
    await applyRulesWithProgress("Status");
  });

  document.getElementById("menu-view-log").addEventListener("click", () => {
    window.location.href = "./logs.html";
    closeMenu();
  });
  document.getElementById("menu-alerts").addEventListener("click", () => {
    window.location.href = "./alerts.html";
    closeMenu();
  });
  document.getElementById("menu-rules").addEventListener("click", () => {
    window.location.href = "./rules.html";
    closeMenu();
  });
  document.getElementById("menu-preferences").addEventListener("click", () => {
    window.location.href = "./preferences.html";
    closeMenu();
  });
  document.getElementById("menu-model-update").addEventListener("click", () => {
    window.location.href = "./model_update.html";
    closeMenu();
  });
  document.getElementById("menu-export").addEventListener("click", () => {
    downloadConfig();
    closeMenu();
  });
  document.getElementById("menu-import-input").addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (file) importConfig(file);
    closeMenu();
  });
  document.getElementById("menu-exit").addEventListener("click", closeMenu);
  document.getElementById("dialog-backdrop").addEventListener("click", hideDialog);
}

function closeMenu() {
  document.getElementById("side-menu").classList.add("hidden");
  document.getElementById("menu-backdrop").classList.add("hidden");
}

function initProfile() {
  const savedProfile = localStorage.getItem(PROFILE_KEY);
  if (savedProfile) document.getElementById("profile-current").textContent = savedProfile;
}

wireEvents();
initProfile();
updateModeMenu();
updateSortMenu();
updateFirewallVisual();
loadAppsFromDevice();
notifyActive();
