"use strict";

/* ---------- tiny helpers ---------- */
const $ = (selector, root = document) => root.querySelector(selector);

// Build DOM nodes without innerHTML, so entry text can never run as HTML.
function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value == null || value === false) continue;
    if (key === "class") el.className = value;
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else if (value === true) el.setAttribute(key, "");
    else el.setAttribute(key, value);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(kid));
  }
  return el;
}

async function api(path, { method = "GET", body, raw = false } = {}) {
  const res = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  if (!(raw && res.ok)) {
    try { data = await res.json(); } catch { /* empty body */ }
  }
  if (res.status === 401 && data.locked) {
    await showAuth("Vault locked. Enter your master password to continue.");
    throw new Error("locked");
  }
  if (!res.ok) throw new Error(data.error || "Something went wrong.");
  return raw ? res : data;
}

let toastTimer;
function toast(message) {
  const el = $("#toast");
  el.textContent = message;
  el.classList.add("on");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("on"), 2800);
}

let clipboardTimer;
async function copyText(text, label, clearAfter = 0) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    toast("Couldn't copy. Select the text and copy it manually.");
    return;
  }
  clearTimeout(clipboardTimer);
  if (clearAfter) {
    clipboardTimer = setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), clearAfter * 1000);
    toast(`${label} copied. Clipboard clears in ${clearAfter} seconds.`);
  } else {
    toast(`${label} copied.`);
  }
}

// Letters stay plain, digits turn teal, symbols turn brass and bold,
// so look-alike characters (0/O, 1/l, I) are easy to tell apart.
function colorize(text) {
  const frag = document.createDocumentFragment();
  for (const ch of text) {
    let cls = "";
    if (/[0-9]/.test(ch)) cls = "c-digit";
    else if (!/[A-Za-z]/.test(ch)) cls = "c-symbol";
    frag.append(cls ? h("span", { class: cls }, ch) : document.createTextNode(ch));
  }
  return frag;
}

function formatDate(iso) {
  return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

function bindShowToggle(button, input) {
  button.addEventListener("click", () => {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    button.textContent = show ? "Hide" : "Show";
  });
}

/* ---------- state ---------- */
const state = { entries: [], selectedId: null, revealed: null, query: "", breach: null, health: null };
const minMaster = Number(document.body.dataset.minMaster);

/* ---------- create / unlock ---------- */
let vaultExists = false;

async function showAuth(message = "") {
  state.breach = null;
  state.health = null;
  state.entries = [];
  state.selectedId = null;
  state.revealed = null;
  $("#app").hidden = true;
  $("#auth").hidden = false;
  $("#search").value = "";
  state.query = "";
  for (const d of document.querySelectorAll("dialog[open]")) d.close();
  for (const f of document.querySelectorAll("dialog form")) f.reset();

  const { exists } = await fetch("/api/status").then((r) => r.json());
  vaultExists = exists;
  $("#confirm-wrap").hidden = exists;
  $("#auth-submit").textContent = exists ? "Unlock vault" : "Create vault";
  $("#auth-lede").textContent = exists
    ? "Your passwords are encrypted on this computer."
    : `Choose a master password of at least ${minMaster} characters. It encrypts everything, and there is no way to recover it if you forget it.`;
  $("#auth-error").textContent = message;
  $("#master").value = "";
  $("#master-confirm").value = "";
  $("#master").focus();
}

$("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const master = $("#master").value;
  $("#auth-error").textContent = "";
  try {
    if (!vaultExists) {
      if (master !== $("#master-confirm").value) {
        $("#auth-error").textContent = "The two master passwords don't match.";
        return;
      }
      await api("/api/setup", { method: "POST", body: { master } });
    } else {
      await api("/api/unlock", { method: "POST", body: { master } });
    }
    $("#master").value = "";
    $("#master-confirm").value = "";
    await showApp();
  } catch (err) {
    if (err.message !== "locked") $("#auth-error").textContent = err.message;
  }
});

$("#auth-check").addEventListener("click", () => openCheck());

/* ---------- main screen ---------- */
async function showApp() {
  $("#auth").hidden = true;
  $("#app").hidden = false;
  $("#app").classList.remove("show-detail");
  await loadEntries();
}

async function loadEntries() {
  const { entries } = await api(`/api/entries?q=${encodeURIComponent(state.query)}`);
  state.entries = entries;
  if (!entries.some((e) => e.id === state.selectedId)) {
    state.selectedId = null;
    state.revealed = null;
  }
  renderList();
  renderDetail();
}

function renderList() {
  const list = $("#list");
  list.replaceChildren();

  if (state.entries.length === 0) {
    list.append(
      state.query
        ? h("div", { class: "empty" },
            h("p", { class: "empty-title" }, "No matches"),
            h("p", {}, `Nothing in your vault matches "${state.query}".`))
        : h("div", { class: "empty" },
            h("p", { class: "empty-title" }, "Your vault is empty"),
            h("p", {}, "Add the first account you want to keep safe."),
            h("button", { class: "btn btn-primary", type: "button", onclick: () => openEntryForm() }, "Add entry"))
    );
    return;
  }

  for (const entry of state.entries) {
    list.append(
      h("button", {
        class: "item",
        type: "button",
        "aria-current": entry.id === state.selectedId ? "true" : "false",
        onclick: () => selectEntry(entry.id),
      },
        h("span", { class: "item-name" }, entry.name),
        h("span", { class: "item-sub" }, entry.username || entry.url || "No username"))
    );
  }
}

function selectEntry(id) {
  state.selectedId = id;
  state.breach = null;
  state.revealed = null;
  $("#app").classList.add("show-detail");
  renderList();
  renderDetail();
}

function field(label, valueNode, actions) {
  return h("div", { class: "field" },
    h("div", { class: "field-label" }, label),
    h("div", { class: "field-line" },
      h("div", { class: "field-value" }, valueNode),
      actions ? h("div", { class: "field-actions" }, actions) : null));
}

function renderDetail() {
  const pane = $("#detail");
  pane.replaceChildren();
  const entry = state.entries.find((e) => e.id === state.selectedId);

  if (!entry) {
    pane.append(h("p", { class: "detail-empty" },
      state.entries.length ? "Select an entry to see its details." : "Entries you add will show up here."));
    return;
  }

  const none = () => h("span", { class: "none" }, "Not set");  // a new element each time
  const isLink = /^https?:\/\//i.test(entry.url);

  const secret = state.revealed !== null
    ? h("div", { class: "secret" }, colorize(state.revealed))
    : h("div", { class: "secret secret-hidden" }, "\u2022".repeat(12));

  pane.append(h("div", { class: "detail-inner" },
    h("button", { class: "btn btn-quiet btn-small back", type: "button",
      onclick: () => $("#app").classList.remove("show-detail") }, "Back to entries"),
    h("h2", { class: "detail-title" }, entry.name),
    h("p", { class: "detail-meta" },
      `Added ${formatDate(entry.created)}`,
      entry.updated !== entry.created ? `. Updated ${formatDate(entry.updated)}` : ""),

    field("Username or email", entry.username ? entry.username : none(),
      entry.username ? h("button", { class: "btn btn-small", type: "button",
        onclick: () => copyText(entry.username, "Username") }, "Copy") : null),

    h("div", { class: "field" },
      h("div", { class: "field-label" }, "Password"),
      h("div", { class: "field-line" },
        h("div", { class: "field-value" }, secret),
        h("div", { class: "field-actions" },
          h("button", { class: "btn btn-small", type: "button", onclick: toggleReveal },
            state.revealed !== null ? "Hide" : "Show"),
          h("button", { class: "btn btn-small", type: "button", onclick: copyPassword }, "Copy"))),
      state.revealed !== null
        ? h("p", { class: "hint legend" }, "Digits are teal and symbols are brass, so look-alike characters are easy to tell apart.")
        : null,
      breachBox(entry.id)),

    field("Website",
      entry.url ? (isLink ? h("a", { href: entry.url, target: "_blank", rel: "noopener noreferrer" }, entry.url) : entry.url) : none()),
    field("Notes", entry.notes ? h("p", { class: "notes-text" }, entry.notes) : none()),

    h("div", { class: "detail-actions" },
      h("button", { class: "btn", type: "button", onclick: () => openEntryForm(entry) }, "Edit"),
      h("button", { class: "btn", type: "button", onclick: () => openDelete(entry) }, "Delete"))));
}

async function fetchPassword(id) {
  const { password } = await api(`/api/entries/${id}/password`);
  return password;
}

async function toggleReveal() {
  if (state.revealed !== null) {
    state.revealed = null;
  } else {
    try { state.revealed = await fetchPassword(state.selectedId); } catch { return; }
  }
  renderDetail();
}

async function copyPassword() {
  try {
    const password = state.revealed ?? await fetchPassword(state.selectedId);
    await copyText(password, "Password", 20);
  } catch { /* shown by api() */ }
}

/* ---------- search ---------- */
let searchTimer;
$("#search").addEventListener("input", (event) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    state.query = event.target.value;
    loadEntries().catch(() => {});
  }, 120);
});

document.addEventListener("keydown", (event) => {
  const typing = /^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName);
  if (event.key === "/" && !typing && !$("#app").hidden && !document.querySelector("dialog[open]")) {
    event.preventDefault();
    $("#search").focus();
  }
});

/* ---------- add / edit ---------- */
let editingId = null;

async function openEntryForm(entry = null, { replacement = false } = {}) {
  editingId = entry ? entry.id : null;
  $("#entry-title").textContent = replacement ? "Replace password" : entry ? "Edit entry" : "Add entry";
  $("#entry-note").hidden = !replacement;
  $("#entry-error").textContent = "";
  $("#f-name").value = entry ? entry.name : "";
  $("#f-username").value = entry ? entry.username : "";
  $("#f-url").value = entry ? entry.url : "";
  $("#f-notes").value = entry ? entry.notes : "";
  $("#f-password").value = "";
  $("#f-password").type = "password";
  $("#f-show").textContent = "Show";
  if (entry) {
    try { $("#f-password").value = await fetchPassword(entry.id); } catch { return; }
  }
  if (replacement) {
    try {
      const { password } = await api("/api/generate", { method: "POST", body: {} });
      $("#f-password").value = password;
      $("#f-password").type = "text";
      $("#f-show").textContent = "Hide";
    } catch { return; }
  }
  $("#entry-dialog").showModal();
  $("#f-name").focus();
}

bindShowToggle($("#f-show"), $("#f-password"));
$("#add-btn").addEventListener("click", () => openEntryForm());
$("#entry-cancel").addEventListener("click", () => $("#entry-dialog").close());
// Clear the password field however the dialog closes (Cancel, Save or Esc).
$("#entry-dialog").addEventListener("close", () => { $("#f-password").value = ""; });
$("#f-copy").addEventListener("click", () => {
  const value = $("#f-password").value;
  if (value) copyText(value, "Password", 20);
});

$("#f-generate").addEventListener("click", async () => {
  try {
    const { password } = await api("/api/generate", { method: "POST", body: {} });
    $("#f-password").value = password;
    $("#f-password").type = "text";
    $("#f-show").textContent = "Hide";
  } catch (err) { $("#entry-error").textContent = err.message; }
});

$("#f-check").addEventListener("click", () => {
  // Words from this entry: a password containing them is rated lower.
  const context = [$("#f-name").value, $("#f-username").value.split("@")[0]];
  openCheck($("#f-password").value, (password) => {
    $("#f-password").value = password;
  }, context);
});

$("#entry-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const body = {
    name: $("#f-name").value,
    username: $("#f-username").value,
    password: $("#f-password").value,
    url: $("#f-url").value,
    notes: $("#f-notes").value,
  };
  try {
    const result = editingId
      ? await api(`/api/entries/${editingId}`, { method: "PUT", body })
      : await api("/api/entries", { method: "POST", body });
    $("#f-password").value = "";
    $("#entry-dialog").close();
    state.selectedId = result.entry.id;
    state.revealed = null;
    $("#app").classList.add("show-detail");
    await loadEntries();
    markHealthStale(result.entry.id);
    toast(editingId ? "Entry saved." : "Entry added.");
  } catch (err) {
    if (err.message !== "locked") $("#entry-error").textContent = err.message;
  }
});

/* ---------- delete ---------- */
function openDelete(entry) {
  $("#delete-title").textContent = `Delete ${entry.name}?`;
  $("#delete-confirm").onclick = async () => {
    try {
      await api(`/api/entries/${entry.id}`, { method: "DELETE" });
      $("#delete-dialog").close();
      state.selectedId = null;
      state.revealed = null;
      $("#app").classList.remove("show-detail");
      await loadEntries();
      markHealthStale(entry.id);
      toast("Entry deleted.");
    } catch { /* shown by api() */ }
  };
  $("#delete-dialog").showModal();
  $("#delete-cancel").focus();
}
$("#delete-cancel").addEventListener("click", () => $("#delete-dialog").close());

/* ---------- strength check ---------- */
let useCallback = null;
let checkContext = [];
let currentSuggestion = "";

function openCheck(initial = "", onUse = null, context = []) {
  useCallback = onUse;
  checkContext = context;
  $("#check-input").value = initial;
  $("#check-input").type = "password";
  $("#check-show").textContent = "Show";
  $("#check-error").textContent = "";
  $("#check-result").replaceChildren();
  $("#check-dialog").showModal();
  $("#check-input").focus();
  if (initial) runCheck();
}

bindShowToggle($("#check-show"), $("#check-input"));
$("#check-btn").addEventListener("click", () => openCheck());
$("#check-close").addEventListener("click", () => $("#check-dialog").close());
$("#check-dialog").addEventListener("close", () => {
  $("#check-input").value = "";
  $("#check-result").replaceChildren();
  currentSuggestion = "";
});

$("#check-form").addEventListener("submit", (event) => {
  event.preventDefault();
  runCheck();
});

async function runCheck() {
  $("#check-error").textContent = "";
  try {
    const result = await api("/api/check", { method: "POST", body: { password: $("#check-input").value, context: checkContext } });
    renderCheck(result);
  } catch (err) {
    $("#check-result").replaceChildren();
    if (err.message !== "locked") $("#check-error").textContent = err.message;
  }
}

const LEVELS = ["VERY WEAK", "WEAK", "MEDIUM", "STRONG", "VERY STRONG"];
const levelText = (name) => name.charAt(0) + name.slice(1).toLowerCase();

function renderCheck(r) {
  const level = LEVELS.indexOf(r.strength);
  const box = $("#check-result");
  box.replaceChildren(
    h("div", {},
      h("div", { class: "verdict", "data-level": String(level) },
        h("span", { class: "verdict-label" }, levelText(r.strength)),
        h("span", { class: "hint" }, `Estimated time to crack: ${r.crack_time}`)),
      h("div", { class: "meter", "data-level": String(level), "aria-hidden": "true" },
        h("span"), h("span"), h("span"), h("span"), h("span"))),

    r.issues.length
      ? h("ul", { class: "review-list" }, r.issues.map((text) => h("li", {}, text)))
      : h("p", {}, "No problems found."),

    h("p", { class: "hint" }, "Based on an offline attack against a slow hash such as bcrypt. Weak passwords fall much faster."),

    h("ul", { class: "checks" },
      Object.entries(r.checks).map(([label, ok]) =>
        h("li", { class: ok ? "check-pass" : "check-fail" }, label))),

    r.suggestion ? suggestionBlock(r.suggestion) : null,
    dialogBreachBox());
}

function suggestionBlock(s) {
  currentSuggestion = s.password;
  return h("div", { class: "suggestion", id: "suggestion" },
    h("p", { class: "suggestion-title" }, "A stronger password based on yours"),
    h("div", { class: "secret", id: "suggestion-text" }, colorize(s.password)),
    h("p", { class: "hint", id: "suggestion-note" },
      `Rated ${levelText(s.strength).toLowerCase()}. It keeps the shape of your original, which makes it easier to remember and also a little easier to guess than a fully random password.`),
    h("div", { class: "suggestion-actions" },
      h("button", { class: "btn btn-small", type: "button", onclick: () => copyText(currentSuggestion, "Password", 20) }, "Copy"),
      useCallback
        ? h("button", { class: "btn btn-primary btn-small", type: "button", onclick: useSuggestion }, "Use this password")
        : null,
      h("button", { class: "btn btn-small", type: "button", onclick: checkSuggestion }, "Check this one"),
      h("button", { class: "btn btn-small", type: "button", onclick: randomInstead }, "Fully random instead")));
}

function useSuggestion() {
  if (useCallback) useCallback(currentSuggestion);
  $("#check-dialog").close();
  toast("Password added to the form.");
}

function checkSuggestion() {
  $("#check-input").value = currentSuggestion;
  runCheck();
}

async function randomInstead() {
  try {
    const { password } = await api("/api/generate", { method: "POST", body: {} });
    currentSuggestion = password;
    $("#suggestion-text").replaceChildren(colorize(password));
    $("#suggestion-note").textContent = "Fully random, with no link to your original password.";
  } catch (err) { $("#check-error").textContent = err.message; }
}

/* ---------- settings: master password, backup, restore ---------- */
function clearSettings() {
  for (const form of document.querySelectorAll("#settings-dialog form")) form.reset();
  for (const msg of document.querySelectorAll("#settings-dialog .error")) msg.textContent = "";
}

$("#settings-btn").addEventListener("click", () => {
  clearSettings();
  $("#settings-dialog").showModal();
});
$("#settings-close").addEventListener("click", () => $("#settings-dialog").close());
$("#settings-dialog").addEventListener("close", clearSettings);

$("#master-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const msg = $("#master-msg");
  msg.textContent = "";
  if ($("#mp-new").value !== $("#mp-confirm").value) {
    msg.textContent = "The two new master passwords don't match.";
    return;
  }
  try {
    await api("/api/change-master", {
      method: "POST",
      body: { old: $("#mp-old").value, new: $("#mp-new").value },
    });
    clearSettings();
    toast("Master password changed.");
  } catch (err) {
    if (err.message !== "locked") msg.textContent = err.message;
  }
});

$("#export-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const msg = $("#export-msg");
  msg.textContent = "";
  const backupPassword = $("#ex-backup").value;
  if (backupPassword !== $("#ex-confirm").value) {
    msg.textContent = "The two backup passwords don't match.";
    return;
  }
  try {
    const res = await api("/api/export", {
      method: "POST",
      body: { master: $("#ex-master").value, backup_password: backupPassword },
      raw: true,
    });
    const url = URL.createObjectURL(await res.blob());
    const link = h("a", { href: url, download: `vault-backup-${new Date().toISOString().slice(0, 10)}.json` });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    clearSettings();
    toast("Backup downloaded.");
  } catch (err) {
    if (err.message !== "locked") msg.textContent = err.message;
  }
});

$("#import-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const msg = $("#import-msg");
  msg.textContent = "";
  const file = $("#im-file").files[0];
  if (!file) {
    msg.textContent = "Choose a backup file first.";
    return;
  }
  if (file.size > 4 * 1024 * 1024) {
    msg.textContent = "That file is too large to be a Vault backup.";
    return;
  }
  try {
    const result = await api("/api/import", {
      method: "POST",
      body: { backup: await file.text(), password: $("#im-password").value },
    });
    clearSettings();
    await loadEntries();
    markHealthStale();
    const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
    toast(`Imported ${plural(result.added, "entry", "entries")}. Skipped ${plural(result.skipped, "duplicate", "duplicates")}.`);
  } catch (err) {
    if (err.message !== "locked") msg.textContent = err.message;
  }
});

/* ---------- breach check (optional, runs only when you press the button) ---------- */
const BREACH_NOTE = "Optional. Sends only the first 5 characters of a one-way hash to haveibeenpwned.com. The password itself never leaves this computer.";

function describeBreach(result) {
  if (result.found) {
    return {
      cls: "breach-found",
      text: `Seen ${result.count.toLocaleString()} times in known data breaches. Don't use it anywhere, and change it on any site that still uses it.`,
    };
  }
  return {
    cls: "breach-clear",
    text: "Not found in known breaches. That doesn't prove it is safe, only that it hasn't appeared in public leaks.",
  };
}

function breachBox(entryId) {
  const shown = state.breach && state.breach.id === entryId ? state.breach : null;
  return h("div", { class: "breach" },
    h("div", { class: "breach-row" },
      h("button", { class: "btn btn-small", type: "button", onclick: breachFromEntry }, "Check if leaked"),
      shown ? h("span", { class: `breach-result ${shown.cls}`, role: "status" }, shown.text) : null),
    h("p", { class: "hint" }, BREACH_NOTE));
}

async function breachFromEntry() {
  const id = state.selectedId;
  state.breach = { id, cls: "", text: "Checking\u2026" };
  renderDetail();
  try {
    const result = await api(`/api/entries/${id}/breach-check`, { method: "POST", body: {} });
    state.breach = { id, ...describeBreach(result) };
  } catch (err) {
    if (err.message === "locked") return;
    state.breach = { id, cls: "breach-error", text: err.message };
  }
  if (state.selectedId === id) renderDetail();
}

async function breachFromDialog() {
  const out = $("#breach-result");
  const button = $("#breach-btn");
  out.className = "breach-result";
  out.textContent = "Checking\u2026";
  button.disabled = true;
  try {
    const result = await api("/api/breach-check", { method: "POST", body: { password: $("#check-input").value } });
    const described = describeBreach(result);
    out.className = `breach-result ${described.cls}`;
    out.textContent = described.text;
  } catch (err) {
    if (err.message === "locked") return;
    out.className = "breach-result breach-error";
    out.textContent = err.message;
  } finally {
    button.disabled = false;
  }
}

function dialogBreachBox() {
  return h("div", { class: "breach" },
    h("div", { class: "breach-row" },
      h("button", { id: "breach-btn", class: "btn btn-small", type: "button", onclick: breachFromDialog }, "Check if leaked"),
      h("span", { id: "breach-result", class: "breach-result", role: "status" })),
    h("p", { class: "hint" }, BREACH_NOTE));
}

/* ---------- password health (scan runs only when you press the button) ---------- */
// state.health = { data, breach: {id: result}, stale, confirmAll, progress } or null

function markHealthStale(entryId) {
  if (!state.health) return;
  state.health.stale = true;
  if (entryId) delete state.health.breach[entryId];  // its password may have changed
}

$("#health-btn").addEventListener("click", () => {
  renderHealth();
  $("#health-dialog").showModal();
});
$("#health-close").addEventListener("click", () => $("#health-dialog").close());

$("#health-scan").addEventListener("click", async () => {
  const button = $("#health-scan");
  button.disabled = true;
  button.textContent = "Scanning\u2026";
  try {
    const data = await api("/api/health/scan", { method: "POST", body: {} });
    state.health = {
      data,
      breach: state.health ? state.health.breach : {},
      stale: false,
      confirmAll: false,
      progress: null,
    };
  } catch (err) {
    if (err.message !== "locked") toast(err.message);
  } finally {
    button.disabled = false;
  }
  renderHealth();
});

const breachOf = (id) => (state.health && state.health.breach[id]) || null;
const wasChecked = (b) => b && typeof b.found === "boolean";

function stat(value, label, sub, bad = false) {
  return h("div", { class: "stat" },
    h("span", { class: `stat-num${bad && value > 0 ? " bad" : ""}` }, String(value)),
    h("span", { class: "stat-label" }, label),
    sub ? h("span", { class: "stat-sub" }, sub) : null);
}

function priorityOf(entry) {
  const b = breachOf(entry.id);
  return (wasChecked(b) && b.found) || entry.weak ? "high" : "review";
}

function reasonsFor(entry) {
  const items = [];
  if (entry.weak) {
    items.push(h("li", {},
      `Weak password: rated ${levelText(entry.strength).toLowerCase()}.`,
      entry.issues.length ? h("div", { class: "reason-sub" }, entry.issues.join(" ")) : null));
  }
  if (entry.reused) {
    const others = entry.reused_with;
    const shown = others.slice(0, 3).join(", ") + (others.length > 3 ? ` and ${others.length - 3} more` : "");
    items.push(h("li", {}, `Same password as ${shown}.`));
  }
  const b = breachOf(entry.id);
  if (b && b.checking) items.push(h("li", { class: "reason-sub" }, "Checking for leaks\u2026"));
  else if (b && b.error) items.push(h("li", { class: "reason-sub" }, `Leak check failed: ${b.error}`));
  else if (wasChecked(b)) {
    items.push(h("li", { class: b.found ? "breach-found" : "breach-clear" },
      b.found ? describeBreach(b).text : "Not found in known breaches."));
  }
  return items;
}

async function openEntryFromHealth(id) {
  $("#health-dialog").close();
  $("#search").value = "";
  state.query = "";
  await loadEntries();
  selectEntry(id);
}

async function replaceFromHealth(id) {
  const entry = state.entries.find((e) => e.id === id);
  if (!entry) return;
  $("#health-dialog").close();
  await openEntryForm(entry, { replacement: true });
}

async function healthCheckLeak(id) {
  const health = state.health;
  health.breach[id] = { checking: true };
  renderHealth();
  try {
    health.breach[id] = await api(`/api/entries/${id}/breach-check`, { method: "POST", body: {} });
  } catch (err) {
    if (err.message === "locked") return;
    health.breach[id] = { error: err.message };
  }
  if (state.health === health) renderHealth();
}

async function healthCheckAll() {
  const health = state.health;
  health.confirmAll = false;
  const ids = health.data.entries.map((e) => e.id);
  for (let i = 0; i < ids.length; i++) {
    if (state.health !== health) return;
    health.progress = `Checking ${i + 1} of ${ids.length}\u2026`;
    renderHealth();
    try {
      health.breach[ids[i]] = await api(`/api/entries/${ids[i]}/breach-check`, { method: "POST", body: {} });
    } catch (err) {
      if (err.message === "locked") return;
      health.breach[ids[i]] = { error: err.message };
      break;  // most likely offline: stop instead of failing for every entry
    }
  }
  health.progress = null;
  if (state.health === health) renderHealth();
}

function renderHealth() {
  const body = $("#health-body");
  body.replaceChildren();
  const health = state.health;
  $("#health-scan").textContent = health ? "Scan again" : "Scan vault";

  if (!health) {
    body.append(h("p", {}, "Nothing scanned yet. Press Scan vault to check your saved passwords for weak and reused ones."));
    return;
  }

  const { data } = health;
  if (health.stale) {
    body.append(h("p", { class: "stale", role: "status" }, "Your vault has changed since this scan. Scan again to refresh these results."));
  }
  if (data.total === 0) {
    body.append(h("p", {}, "Your vault is empty. Add entries first, then scan."));
    return;
  }

  const checked = data.entries.filter((e) => wasChecked(breachOf(e.id))).length;
  const breached = data.entries.filter((e) => { const b = breachOf(e.id); return wasChecked(b) && b.found; }).length;

  body.append(h("div", { class: "stats" },
    stat(data.total, data.total === 1 ? "Password checked" : "Passwords checked"),
    stat(data.weak, "Weak", "Very weak or weak", true),
    stat(data.reused, "Reused", data.reused_groups ? `In ${data.reused_groups} ${data.reused_groups === 1 ? "group" : "groups"}` : "Each one is unique", true),
    stat(breached, "Known breached", `${checked} of ${data.total} checked`, true)));

  const flagged = data.entries
    .filter((e) => e.weak || e.reused || (wasChecked(breachOf(e.id)) && breachOf(e.id).found))
    .sort((a, b) => (priorityOf(a) === "high" ? 0 : 1) - (priorityOf(b) === "high" ? 0 : 1));

  if (flagged.length === 0) {
    body.append(h("p", {}, "No weak or reused passwords found."));
  } else {
    body.append(h("div", { class: "issues" }, flagged.map((entry) => {
      const priority = priorityOf(entry);
      const b = breachOf(entry.id);
      return h("div", { class: `issue issue-${priority}` },
        h("div", { class: "issue-top" },
          h("div", {},
            h("span", { class: "issue-name" }, entry.name),
            entry.username ? h("span", { class: "issue-user" }, `  ${entry.username}`) : null),
          h("span", { class: "priority" }, priority === "high" ? "High priority" : "Review")),
        h("ul", { class: "reasons" }, reasonsFor(entry)),
        h("div", { class: "issue-actions" },
          h("button", { class: "btn btn-small", type: "button", onclick: () => openEntryFromHealth(entry.id) }, "Open"),
          h("button", { class: "btn btn-small", type: "button", onclick: () => replaceFromHealth(entry.id) }, "Generate replacement"),
          h("button", { class: "btn btn-small", type: "button", disabled: !!(b && b.checking), onclick: () => healthCheckLeak(entry.id) }, "Check for leaks")));
    })));
  }

  // Breach status is separate and opt-in. An unchecked entry is not known to be safe.
  const total = data.total;
  if (health.confirmAll) {
    body.append(h("div", { class: "confirm-box" },
      h("p", {}, `This sends ${total} ${total === 1 ? "lookup" : "lookups"} to haveibeenpwned.com, one per entry. Each lookup contains only the first 5 characters of a one-way hash. No password is ever sent.`),
      h("div", { class: "issue-actions" },
        h("button", { class: "btn btn-primary btn-small", type: "button", onclick: healthCheckAll }, `Send ${total} ${total === 1 ? "lookup" : "lookups"}`),
        h("button", { class: "btn btn-small", type: "button", onclick: () => { health.confirmAll = false; renderHealth(); } }, "Cancel"))));
  } else {
    body.append(h("div", { class: "issue-actions" },
      h("button", { class: "btn btn-small", type: "button", disabled: !!health.progress, onclick: () => { health.confirmAll = true; renderHealth(); } },
        health.progress || "Check all entries for leaks"),
      h("span", { class: "hint" }, `Breach status: ${checked} of ${total} checked. An entry you haven't checked isn't known to be safe.`)));
  }
}

/* ---------- lock ---------- */
$("#lock-btn").addEventListener("click", async () => {
  await fetch("/api/lock", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  await showAuth();
});

// The server locks after 5 idle minutes; this notices and updates the screen.
setInterval(async () => {
  if ($("#app").hidden) return;
  const { unlocked } = await fetch("/api/status").then((r) => r.json()).catch(() => ({ unlocked: true }));
  if (!unlocked) await showAuth("Vault locked after 5 minutes of inactivity.");
}, 15000);

/* ---------- start ---------- */
(async function init() {
  const { exists, unlocked } = await fetch("/api/status").then((r) => r.json());
  vaultExists = exists;
  if (unlocked) await showApp();
  else await showAuth();
})();
