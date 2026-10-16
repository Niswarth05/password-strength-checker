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
const state = { entries: [], selectedId: null, revealed: null, query: "" };
const minMaster = Number(document.body.dataset.minMaster);

/* ---------- create / unlock ---------- */
let vaultExists = false;

async function showAuth(message = "") {
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

  const none = h("span", { class: "none" }, "Not set");
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

    field("Username or email", entry.username ? entry.username : none,
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
        : null),

    field("Website",
      entry.url ? (isLink ? h("a", { href: entry.url, target: "_blank", rel: "noopener noreferrer" }, entry.url) : entry.url) : none),
    field("Notes", entry.notes ? h("p", { class: "notes-text" }, entry.notes) : none),

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

async function openEntryForm(entry = null) {
  editingId = entry ? entry.id : null;
  $("#entry-title").textContent = entry ? "Edit entry" : "Add entry";
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
  $("#entry-dialog").showModal();
  $("#f-name").focus();
}

bindShowToggle($("#f-show"), $("#f-password"));
$("#add-btn").addEventListener("click", () => openEntryForm());
$("#entry-cancel").addEventListener("click", () => { $("#f-password").value = ""; $("#entry-dialog").close(); });

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

    r.suggestion ? suggestionBlock(r.suggestion) : null);
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
    const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
    toast(`Imported ${plural(result.added, "entry", "entries")}. Skipped ${plural(result.skipped, "duplicate", "duplicates")}.`);
  } catch (err) {
    if (err.message !== "locked") msg.textContent = err.message;
  }
});

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
